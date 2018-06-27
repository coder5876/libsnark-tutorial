#include "libsnark/gadgetlib1/gadget.hpp"

using namespace libsnark;

template<typename FieldT>
class test_gadget : public gadget<FieldT> {
private:
  pb_variable<FieldT> sym_1;
  pb_variable<FieldT> y;
  pb_variable<FieldT> sym_2;
public:
  const pb_variable<FieldT> out;
  const pb_variable<FieldT> x;

  test_gadget(protoboard<FieldT> &pb,
              const pb_variable<FieldT> &out,
              const pb_variable<FieldT> &x) : 
    gadget<FieldT>(pb, "poly_gadget"), out(out), x(x)
  {
    // Allocate variables to protoboard
    // The strings (like "x") are only for debugging purposes
	  
    sym_1.allocate(this->pb, "sym_1");
    y.allocate(this->pb, "y");
    sym_2.allocate(this->pb, "sym_2");
  }

  void generate_r1cs_constraints()
  {
    // x*x = sym_1
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, sym_1));

    // sym_1 * x = y
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_1, x, y));

    // y + x = sym_2
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(y + x, 1, sym_2));

    // sym_2 + 5 = ~out
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_2 + 5, 1, out));
  }

  void generate_r1cs_witness()
  {
    this->pb.val(sym_1) = this->pb.val(x) * this->pb.val(x);
    this->pb.val(y) = this->pb.val(sym_1) * this->pb.val(x);
    this->pb.val(sym_2) = this->pb.val(y) + this->pb.val(x);
  }
};
