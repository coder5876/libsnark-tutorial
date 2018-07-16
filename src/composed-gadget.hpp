#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "poly_gadget.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

const size_t sha_digest_len = 256;

const bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

template<typename FieldT>
class test_gadget : public gadget<FieldT> {
private:
  // poly gadget

  shared_ptr<poly_gadget<FieldT>> poly;

  // sha gadget

  shared_ptr<block_variable<FieldT>> h_block;
  shared_ptr<sha256_compression_function_gadget<FieldT>> sha;

  // sha inputs

  shared_ptr<digest_variable<FieldT>> hash;

  pb_variable<FieldT> poly_out;
  pb_variable_array<FieldT> poly_out_array;

  pb_variable<FieldT> zero;
  pb_variable_array<FieldT> padding_var;
public:
  pb_variable_array<FieldT> out;
  pb_variable<FieldT> x;
  
  test_gadget(protoboard<FieldT> &pb,
              pb_variable_array<FieldT> &out,
              pb_variable<FieldT> &x) : 
    gadget<FieldT>(pb, "gadget"), out(out), x(x)
  {
    poly_out.allocate(this->pb, "poly_out");

    poly.reset(new poly_gadget<FieldT>(this->pb, poly_out, this->x));

    poly_out_array.allocate(this->pb, sha_digest_len, "poly_out_array");

    zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

    // sha256 padding

    for (size_t i = 0; i < 256; i++) {
      if (sha256_padding[i]) {
        padding_var.emplace_back(ONE);
      }else {
        padding_var.emplace_back(zero);
      }
    }

    pb_linear_combination_array<FieldT> IV = SHA256_default_IV(this->pb);

    h_block.reset(new block_variable<FieldT>(this->pb, {
            poly_out_array,
            padding_var
    }, "h_r1_block"));

    hash.reset(new digest_variable<FieldT>(this->pb, sha_digest_len, "hash"));

    sha.reset(new sha256_compression_function_gadget<FieldT>(this->pb, IV, h_block->bits, *hash, "sha"));
  }

  void generate_r1cs_constraints()
  {
    poly->generate_r1cs_constraints();
    sha->generate_r1cs_constraints();

    // hacky packing stuff

    FieldT twoi = FieldT::one();
    vector<linear_term<FieldT>> sum;
    for(int i=poly_out_array.size()-1; i>=0; i--) {
      sum.emplace_back(twoi * poly_out_array[i]);

      twoi += twoi;
    }
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(linear_combination<FieldT>(sum), 1, this->poly_out));

    for(size_t i=0; i<out.size(); i++) {
      this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(out[i], 1, hash->bits[i]));
    }
  }

  void generate_r1cs_witness()
  {
    FieldT v = this->pb.val(x);

    this->pb.val(poly_out) = v*v*v + v + 5;

    poly->generate_r1cs_witness();
    
    // fill poly_out with bits of poly->out

    bigint<FieldT::num_limbs> o = this->pb.val(poly_out).as_bigint();
    for(int i=0; i<poly_out_array.size(); i++) {
      this->pb.val(poly_out_array[poly_out_array.size()-1-i]) = o.test_bit(i) ? FieldT::one() : FieldT::zero();
    }

    sha->generate_r1cs_witness();

    this->pb.val(zero) = FieldT::zero();
  }
};
