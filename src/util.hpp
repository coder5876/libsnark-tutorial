#include <fstream>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libff/algebra/curves/public_params.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

template<typename ppT>
void print_vk_to_file(r1cs_ppzksnark_verification_key<ppT> vk, string pathToFile)
{
  ofstream vk_data;
  vk_data.open(pathToFile);

  G2<ppT> A(vk.alphaA_g2);
  A.to_affine_coordinates();
  G1<ppT> B(vk.alphaB_g1);
  B.to_affine_coordinates();
  G2<ppT> C(vk.alphaC_g2);
  C.to_affine_coordinates();

  G2<ppT> gamma(vk.gamma_g2);
  gamma.to_affine_coordinates();
  G1<ppT> gamma_beta_1(vk.gamma_beta_g1);
  gamma_beta_1.to_affine_coordinates();
  G2<ppT> gamma_beta_2(vk.gamma_beta_g2);
  gamma_beta_2.to_affine_coordinates();

  G2<ppT> Z(vk.rC_Z_g2);
  Z.to_affine_coordinates();

  accumulation_vector<G1<ppT>> IC(vk.encoded_IC_query);
  G1<ppT> IC_0(IC.first);
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

  vk_data << Z.X << endl;
  vk_data << Z.Y << endl;

  vk_data << IC_0.X << endl;
  vk_data << IC_0.Y << endl;

  for(size_t i=0; i<IC.size(); i++) {
    G1<ppT> IC_N(IC.rest[i]);
    IC_N.to_affine_coordinates();
    vk_data << IC_N.X << endl;
    vk_data << IC_N.Y << endl;
  }

  vk_data.close();
}

template<typename ppT>
void print_proof_to_file(r1cs_ppzksnark_proof<ppT> proof, string pathToFile)
{
  ofstream proof_data;
  proof_data.open(pathToFile);

  G1<ppT> A_g(proof.g_A.g);
  A_g.to_affine_coordinates();
  G1<ppT> A_h(proof.g_A.h);
  A_h.to_affine_coordinates();

  G2<ppT> B_g(proof.g_B.g);
  B_g.to_affine_coordinates();
  G1<ppT> B_h(proof.g_B.h);
  B_h.to_affine_coordinates();

  G1<ppT> C_g(proof.g_C.g);
  C_g.to_affine_coordinates();
  G1<ppT> C_h(proof.g_C.h);
  C_h.to_affine_coordinates();

  G1<ppT> H(proof.g_H);
  H.to_affine_coordinates();
  G1<ppT> K(proof.g_K);
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

  proof_data.close();
}