#include <stdlib.h>
#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

#include "composed-gadget.hpp"
#include "util.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

int main()
{
  // Initialize the curve parameters

  default_r1cs_ppzksnark_pp::init_public_params();

  typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
  
  // Create protoboard

  protoboard<FieldT> pb;
  pb_variable_array<FieldT> hash;
  pb_variable_array<FieldT> x;

  // Allocate variables

  hash.allocate(pb, 256, "hash");
  x.allocate(pb, 256, "x");

  // This sets up the protoboard variables
  // so that the first one (out) represents the public
  // input and the rest is private input

  pb.set_input_sizes(256);

  // Initialize gadget

  test_gadget<FieldT> g(pb, hash, x);
  g.generate_r1cs_constraints();
  
  // Add witness values

  bit_vector hash_bv = int_list_to_bits({78,152,
  23,
  135,
  180,
  61,
  171,
  123,
  58,
  147,
  215,
  200,
  83,
  7,
  198,
  244,
  58,
  26,
  58,
  88,
  150,
  57,
  69,
  185,
  62,
  165,
  253,
  53,
  112,
69, 80, 23}, 8);
  hash.fill_with_bits(pb, hash_bv);

  bit_vector x_bv = int_list_to_bits({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
  x.fill_with_bits(pb, x_bv);
  //pb.val(x) = 3;

  g.generate_r1cs_witness();
  
  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

  const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "PB satisfied: " << pb.is_satisfied() << endl;
  //cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Verification status: " << verified << endl;
  bit_vector h = hash.get_bits(pb);

  const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk = keypair.vk;

  //print_vk_to_file<default_r1cs_ppzksnark_pp>(vk, "../build/vk_data");
  //print_proof_to_file<default_r1cs_ppzksnark_pp>(proof, "../build/proof_data");

  return 0;
}
