#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
//#include "poly_gadget.hpp"
#include "square_gadget.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

const size_t sha_digest_len = 256;

bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
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

  // packing gadget

	//shared_ptr<packing_gadget<FieldT>> pack;

  // sha gadget

  shared_ptr<block_variable<FieldT>> h_block;
  shared_ptr<sha256_compression_function_gadget<FieldT>> sha;

  // sha inputs

  shared_ptr<digest_variable<FieldT>> hash;

  //pb_variable<FieldT> poly_out;

  pb_variable<FieldT> zero;
  pb_variable_array<FieldT> padding_var;
public:
  pb_variable_array<FieldT> bits;
  pb_variable_array<FieldT> x;
  
  test_gadget(protoboard<FieldT> &pb,
              pb_variable_array<FieldT> &bits,
              pb_variable_array<FieldT> &x) : 
    gadget<FieldT>(pb, "gadget"), bits(bits), x(x)
  {
    hash.reset(new digest_variable<FieldT>(this->pb, sha_digest_len, "hash"));

    //bits.allocate(this->pb, sha_digest_len, "bits");
    
    //pack.reset(new packing_gadget<FieldT>(this->pb, this->bits, this->x, "pack"));

    zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

    for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
    }

    pb_linear_combination_array<FieldT> IV = SHA256_default_IV(this->pb);

    h_block.reset(new block_variable<FieldT>(pb, {
            this->x,
            padding_var
    }, "h_r1_block"));

    sha.reset(new sha256_compression_function_gadget<FieldT>(this->pb, IV, h_block->bits, *hash, "sha"));
  }

  void generate_r1cs_constraints()
  {
    //pack->generate_r1cs_constraints(true);

  	//this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, 1, poly_out));

    /*for(size_t i=0; i<x.size(); i++) {
      this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x[i], 1, right->bits[i]));
    }*/

    sha->generate_r1cs_constraints();

    for(size_t i=0; i<bits.size(); i++) {
      this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(bits[i], 1, hash->bits[i]));
    }
  }

  void generate_r1cs_witness()
  {
    //pack->generate_r1cs_witness_from_packed();
  	sha->generate_r1cs_witness();
  }
};
