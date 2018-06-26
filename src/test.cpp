#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <boost/optional/optional_io.hpp>

#include "algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/common/utils.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/algebra/curves/public_params.hpp"
#include "libsnark/common/data_structures/accumulation_vector.hpp"


using namespace libsnark;
using namespace std;

int main()
{

  typedef Fr<default_r1cs_ppzksnark_pp> FieldT;

  // Initialize the curve parameters.
  default_r1cs_ppzksnark_pp::init_public_params();
  
  // Create protoboard

  protoboard<FieldT> pb;

  // Define variables

  pb_variable<FieldT> x;
  pb_variable<FieldT> sym_1;
  pb_variable<FieldT> y;
  pb_variable<FieldT> sym_2;
  pb_variable<FieldT> out;

  // Allocate variables to protoboard
  // The strings (like "x") are only for debugging purposes
  
  out.allocate(pb, "out");
  x.allocate(pb, "x");
  sym_1.allocate(pb, "sym_1");
  y.allocate(pb, "y");
  sym_2.allocate(pb, "sym_2");

  // This sets up the protoboard variables
  // so that the first one (out) represents the public
  // input and the rest is private input
  pb.set_input_sizes(1);

  cout << "Number of variables: " << pb.num_variables() << endl;

  // Add R1CS constraints to protoboard

  // x*x = sym_1
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, sym_1));

  // sym_1 * x = y
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_1, x, y));

  // y + x = sym_2
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(y + x, 1, sym_2));

  // sym_2 + 5 = ~out
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_2 + 5, 1, out));
  
  // Add witness values

  pb.val(x) = 3;
  pb.val(out) = 35;
  pb.val(sym_1) = 9;
  pb.val(y) = 27;
  pb.val(sym_2) = 30;

  if (pb.is_satisfied()) {
    cout << "Constraint system is satisfied." << endl;
  }
  else {
    cout << "Constraint system is not satisfied." << endl;
  }

  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
  
  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

  r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

  r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;

  cout << "Verification status: " << verified << endl;

  r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk = keypair.vk;

  ofstream vk_data;
  vk_data.open("vk_data");

  G2<default_r1cs_ppzksnark_pp> A(vk.alphaA_g2);
  A.to_affine_coordinates();
  G1<default_r1cs_ppzksnark_pp> B(vk.alphaB_g1);
  B.to_affine_coordinates();
  G2<default_r1cs_ppzksnark_pp> C(vk.alphaC_g2);
  C.to_affine_coordinates();

  G2<default_r1cs_ppzksnark_pp> gamma(vk.gamma_g2);
  gamma.to_affine_coordinates();
  G1<default_r1cs_ppzksnark_pp> gamma_beta_1(vk.gamma_beta_g1);
  gamma_beta_1.to_affine_coordinates();
  G2<default_r1cs_ppzksnark_pp> gamma_beta_2(vk.gamma_beta_g2);
  gamma_beta_2.to_affine_coordinates();

  G2<default_r1cs_ppzksnark_pp> Z(vk.rC_Z_g2);
  Z.to_affine_coordinates();

  accumulation_vector<G1<default_r1cs_ppzksnark_pp>> IC(vk.encoded_IC_query);
  G1<default_r1cs_ppzksnark_pp> IC_0(IC.first);
  IC_0.to_affine_coordinates();

  vk_data << A.X << endl;
  vk_data << A.Y << endl;

  vk_data << B.X << endl;
  vk_data << B.Y << endl;

  vk_data << C.X << endl;
  vk_data << C.Y << endl;

  vk_data << gamma.X << endl;
  vk_data << gamma.Y << endl;

  vk_data << gamma_beta_1.X << endl;
  vk_data << gamma_beta_1.Y << endl;

  vk_data << gamma_beta_2.X << endl;
  vk_data << gamma_beta_2.Y << endl;

  vk_data << IC_0.X << endl;
  vk_data << IC_0.Y << endl;

  for(size_t i=0; i<IC.size(); i++) {
    G1<default_r1cs_ppzksnark_pp> IC_N(IC.rest[i]);
    IC_N.to_affine_coordinates();
    vk_data << IC_N.X << endl;
    vk_data << IC_N.Y << endl;
  }

  vk_data.close();

  ofstream proof_data;
  proof_data.open("proof_data");

  G1<default_r1cs_ppzksnark_pp> A_g(proof.g_A.g);
  A_g.to_affine_coordinates();
  G1<default_r1cs_ppzksnark_pp> A_h(proof.g_A.h);
  A_h.to_affine_coordinates();

  G2<default_r1cs_ppzksnark_pp> B_g(proof.g_B.g);
  B_g.to_affine_coordinates();
  G1<default_r1cs_ppzksnark_pp> B_h(proof.g_B.h);
  B_h.to_affine_coordinates();

  G1<default_r1cs_ppzksnark_pp> C_g(proof.g_C.g);
  C_g.to_affine_coordinates();
  G1<default_r1cs_ppzksnark_pp> C_h(proof.g_C.h);
  C_h.to_affine_coordinates();

  G1<default_r1cs_ppzksnark_pp> H(proof.g_H);
  H.to_affine_coordinates();
  G1<default_r1cs_ppzksnark_pp> K(proof.g_K);
  K.to_affine_coordinates();

  proof_data << A_g.X << endl;
  proof_data << A_g.Y << endl;

  proof_data << A_h.X << endl;
  proof_data << A_h.Y << endl;

  proof_data << B_g.X << endl;
  proof_data << B_g.Y << endl;

  proof_data << B_h.X << endl;
  proof_data << B_h.Y << endl;

  proof_data << C_g.X << endl;
  proof_data << C_g.Y << endl;

  proof_data << C_h.X << endl;
  proof_data << C_h.Y << endl;

  proof_data << H.X << endl;
  proof_data << H.Y << endl;

  proof_data << K.X << endl;
  proof_data << K.Y << endl;

  cout << "g_H: " << endl;
  G1<default_r1cs_ppzksnark_pp> copy(proof.g_H);
  copy.to_affine_coordinates();
  copy.X.as_bigint().print();

  cout << "g_H hex: " << copy.X << endl;
  //copy.X.as_bigint().print_hex();

  cout << "A: " << endl;
  keypair.vk.alphaA_g2.print();

  cout << "IC: " << endl;
  vk.encoded_IC_query.first.print();
  vk.encoded_IC_query.rest[0].print();

  proof_data.close();

  return 0;
}
