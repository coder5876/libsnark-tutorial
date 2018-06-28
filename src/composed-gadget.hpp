//#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "poly_gadget.hpp"
#include "square_gadget.hpp"

using namespace libsnark;

template<typename FieldT>
class test_gadget : public gadget<FieldT> {
private:
	poly_gadget<FieldT> poly;
	square_gadget<FieldT> square;
public:
  pb_variable<FieldT> out;
  pb_variable<FieldT> x;

  test_gadget(protoboard<FieldT> &pb,
              pb_variable<FieldT> &out,
              pb_variable<FieldT> &x) : 
    gadget<FieldT>(pb, "gadget"), out(out), x(x), poly(pb, x), square(pb, poly.out, out)
  {
  }

  void generate_r1cs_constraints()
  {
  	poly.generate_r1cs_constraints();
  	square.generate_r1cs_constraints();
  }

  void generate_r1cs_witness()
  {
  	poly.generate_r1cs_witness();
  	square.generate_r1cs_witness();
  }
};
