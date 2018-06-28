#include "libsnark/gadgetlib1/gadget.hpp"

using namespace libsnark;

template<typename FieldT>
class square_gadget : public gadget<FieldT> {
public:
  pb_variable<FieldT> out;
  pb_variable<FieldT> x;

  square_gadget(protoboard<FieldT> &pb,
              pb_variable<FieldT> &x,
              pb_variable<FieldT> &out) : 
    gadget<FieldT>(pb, "square_gadget"), x(x), out(out)
  {}

  void generate_r1cs_constraints()
  {
    // x*x = sym_1
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, out));
  }

  void generate_r1cs_witness()
  {}
};
