#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
//#include "poly_gadget.hpp"
#include "square_gadget.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

const size_t sha_digest_len = 256;

template<typename FieldT>
class test_gadget : public gadget<FieldT> {
private:

  // packing gadget

	//shared_ptr<packing_gadget<FieldT>> pack;

  // sha gadget

  shared_ptr<sha256_two_to_one_hash_gadget<FieldT>> sha;

  // sha inputs

  shared_ptr<digest_variable<FieldT>> left;
  shared_ptr<digest_variable<FieldT>> right;
  shared_ptr<digest_variable<FieldT>> hash;

  //pb_variable<FieldT> poly_out;

  bit_vector left_bv;
public:
  pb_variable_array<FieldT> bits;
  pb_variable_array<FieldT> x;
  
  test_gadget(protoboard<FieldT> &pb,
              pb_variable_array<FieldT> &bits,
              pb_variable_array<FieldT> &x) : 
    gadget<FieldT>(pb, "gadget"), bits(bits), x(x)
  {
    left_bv = int_list_to_bits({0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000100}, 32);
  
    left.reset(new digest_variable<FieldT>(this->pb, sha_digest_len, "left"));
    right.reset(new digest_variable<FieldT>(this->pb, sha_digest_len, "right"));
    hash.reset(new digest_variable<FieldT>(this->pb, sha_digest_len, "hash"));

    //bits.allocate(this->pb, sha_digest_len, "bits");
    
    //pack.reset(new packing_gadget<FieldT>(this->pb, this->bits, this->x, "pack"));
    sha.reset(new sha256_two_to_one_hash_gadget<FieldT>(this->pb, *left, *right, *hash, "sha"));
  }

  void generate_r1cs_constraints()
  {
    //pack->generate_r1cs_constraints(true);

  	//this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, 1, poly_out));

    for(size_t i=0; i<x.size(); i++) {
      this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x[i], 1, right->bits[i]));
    }

    sha->generate_r1cs_constraints();

    for(size_t i=0; i<bits.size(); i++) {
      this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(bits[i], 1, hash->bits[i]));
    }
  }

  void generate_r1cs_witness()
  {
    //pack->generate_r1cs_witness_from_packed();
  	left->generate_r1cs_witness(left_bv);
    right->generate_r1cs_witness(bits.get_bits(this->pb));
    sha->generate_r1cs_witness();
  }
};
