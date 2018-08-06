# libsnark tutorial

*By Christian Lundkvist and Sam Mayo*

This is a tutorial intended to cover the very basics of the [libsnark](https://github.com/scipr-lab/libsnark) software library for creating zk-SNARKs. We will demonstrate how to formulate zk-SNARK circuits, create proofs and verify the proofs. We will also cover how to verify proofs in smart contracts on Ethereum.

# Preliminaries

If you are a developer who is completely new to zk-SNARKS I’d recommend reading my [previous post](https://media.consensys.net/introduction-to-zksnarks-with-examples-3283b554fc3b) that introduces zk-SNARKS from a high level.

For a more in-depth description of how zk-SNARKs work under the hood, please read Vitalik’s excellent [three post introduction](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649).

# Quick intro to R1CS
 
A *Rank One Constraint System* (R1CS) is a way to express a computation that makes it amenable to zero knowledge proofs. Basically any computation can be reduced (or flattened) to an R1CS. A single rank one constraint on a vector w is defined as

```
<A, w> * <B,w> = <C, w>
```

Where `A`, `B`, `C` are vectors of the same length as `w`, and `<>` denotes inner product of vectors. A R1CS is then a system of these kinds of equations:

```
<A_1, w> * <B_1,w> = <C_1, w>
<A_2, w> * <B_2,w> = <C_2, w>
...
<A_n, w> * <B_n,w> = <C_n, w>
```

The vector `w` is called a *witness* and zk-SNARK proofs can always be reduced to proving that *the prover knows a witness w such that the R1CS is satisfied*. 

# Building & running tests

The repo is set up according to the [tutorial by Howard Wu](https://github.com/howardwu/libsnark-tutorial). See that tutorial for more info about how to configure the CMake files etc. We will here just cover the basics.

To install the dependencies:

On Ubuntu 16.04 LTS:

```
sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev
```

On Ubuntu 14.04 LTS:

```
sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev
```

In order to download and build the repo:

```
git clone https://github.com/christianlundkvist/libsnark-tutorial.git
cd libsnark-tutorial
mkdir build && cd build && cmake ..
make
```

To run the tests go to the `build` directory and run:

```
./src/test
./src/test-gadget
```

# libsnark components: 1. The Protoboard

In electrical engineering, a *protoboard* or *prototyping board* is used to attach circuits and chips to quickly iterate on designs.

![Protoboard](http://www.whitewing.co.uk/sm_1.jpg)

In the libsnark tool, the protoboard is where our "circuits" (i.e. R1CS and gadgets) will be collected.

The C++ file defining the protoboard is [here](https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/protoboard.hpp). We will first show how to add R1CS to the protoboard.

Recall the example in [Vitalik’s blog post](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649): We want to prove that we know a value x that satisfy the equation

```
x^3 + x + 5 == 35.
```

We can make this a little more general, and say that given a publicly known output value `out`, we want to prove that we know `x` such that

```
x^3 + x + 5 == out.
```

Recall that we can introduce some new variables `sym_1, y, sym_2` and flatten the above equation into the following quadratic equations:

```
x * x = sym_1
sym_1 * x = y
y + x = sym_2
sym_2 + 5 = out
```

We can verify that the above system can be written as an R1CS with 

```
w = [one, x, out, sym_1, y, sym_2]
```

and the vectors `A_1, ..., A_4, B_1, ..., B4, C_1, ..., C_4` are given by

```
A_1 = [0, 1, 0, 0, 0, 0]
A_2 = [0, 0, 0, 1, 0, 0]
A_3 = [0, 1, 0, 0, 1, 0]
A_4 = [5, 0, 0, 0, 0, 1]
B_1 = [0, 1, 0, 0, 0, 0]
B_2 = [0, 1, 0, 0, 0, 0]
B_3 = [1, 0, 0, 0, 0, 0]
B_4 = [1, 0, 0, 0, 0, 0]
C_1 = [0, 0, 0, 1, 0, 0]
C_2 = [0, 0, 0, 0, 1, 0]
C_3 = [0, 0, 0, 0, 0, 1]
C_4 = [0, 0, 1, 0, 0, 0]
```

The original degree 3 polynomial equation has a solution `x=3` and we can verify that the R1CS has a corresponding solution

```
w = [1, 3, 35, 9, 27, 30].
```

Now let’s see how we can enter this R1CS into libsnark, produce proofs and verify them. We will use the `pb_variable` type to declare our variables. See the file `test.cpp` for the full code. 

First lets define the finite field where all our values live, and initialize the curve parameters:

```
typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
default_r1cs_ppzksnark_pp::init_public_params();
```

Next we define the protoboard and the variables we need. Note that the variable `one` is automatically defined in the protoboard.

```
protoboard<FieldT> pb;

pb_variable<FieldT> out;
pb_variable<FieldT> x;
pb_variable<FieldT> sym_1;
pb_variable<FieldT> y;
pb_variable<FieldT> sym_2;
```

Next we need to "allocate" the variables on the protoboard. This will associate the variables to a protoboard and will allow us to use the variables to define R1CS constraints.

```
out.allocate(pb, "out");
x.allocate(pb, "x");
sym_1.allocate(pb, "sym_1");
y.allocate(pb, "y");
sym_2.allocate(pb, "sym_2");
```

Note that we are allocating the `out` variable first. This is because libsnark divides the allocated variables in a protoboard into "primary" (i.e. public) and "auxiliary" (i.e. private) variables. To specify which variables are public and which ones are private we use the protoboard function `set_input_sizes(n)` to specify that the first `n` variables are public, and the rest are private. In our case we have one public variable `out`, so we use

```
pb.set_input_sizes(1);
```

to specify that the variable `out` should be public, and the rest private.

Next let's add the above R1CS constraints to the protoboard. This is straightforward once we have the variables allocated:

```
// x*x = sym_1
pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, sym_1));

// sym_1 * x = y
pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_1, x, y));

// y + x = sym_2
pb.add_r1cs_constraint(r1cs_constraint<FieldT>(y + x, 1, sym_2));

// sym_2 + 5 = out
pb.add_r1cs_constraint(r1cs_constraint<FieldT>(sym_2 + 5, 1, out));
```

Now that we have our circuit in the form of R1CS constraints in the protoboard we can run the Generator and generate proving keys and verification keys for our circuit:

```
const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);
```

Note that the above is the so-called "trusted setup". We can access the proving key through `keypair.pk` and the verification key through `keypair.vk`.

Next we want to generate a proof. For this we need to set the values of the public variables in the protoboard, and also set witness values for the private variables:

```
pb.val(out) = 35;

pb.val(x) = 3;
pb.val(sym_1) = 9;
pb.val(y) = 27;
pb.val(sym_2) = 30;
```

Now that the values are set in the protoboard we can access the public values through `pb.primary_input()` and the private values through `pb.auxiliary_input()`. Let's use the proving key, the public inputs and the private inputs to create a proof that we know the witness values:

```
r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
```

Now that we have a proof we can also verify it, using the previously created `proof`, the verifying key `keypair.vk` and the public input `pb.primary_input()`:

```
bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
```

At this stage the boolean `verified` should have the value `true`, given that we put in the correct values for the witness variables.

# libsnark components: 2. Gadgets

![](https://d3s5r33r268y59.cloudfront.net/09812/products/thumbs/2015-01-26T07:21:38.581Z-mbed1_02.jpg.2560x2560_q85.jpg)

The libsnark library uses *gadgets* to package up R1CS into more manageable pieces and to create cleaner interfaces for developers. They do this by being a wrapper around a protoboard and handling generating R1CS constraints and also generating witness values.

We're going to show how to create a gadget for the example R1CS above in order to make it a bit more manageable.

First we create a new file `src/gadget.hpp` which contains the gadget file. In our case we want the developer using the gadget to be able to set the public variable `out`, as well as the private witness variable `x`, but the gadget itself would take care of the intermediate variables `y`, `sym_1` and `sym_2`.

Thus we create a class `test_gadget`, derived from the base `gadget` class which has the variables `y`, `sym_1` and `sym_2` as private members (in the C++ sense). The variables `x` and `out` will be public class member variables.

In the following sections we go over the functions of this gadget and how to use it.

## Constructor

As any gadget, the constructor takes as input a protoboard `pb`. We also have `pb_variable` inputs `x` and `out`. We assume that the user of the gadget has already allocated `x` and `out` to the protoboard.

The constructor then allocates the intermediate variables to the protoboard:

```
sym_1.allocate(this->pb, "sym_1");
y.allocate(this->pb, "y");
sym_2.allocate(this->pb, "sym_2");
```

## Function `generate_r1cs_constraints()`

This function adds the R1CS constraints corresponding to the circuits. These are the same constraints as we added manually earlier, just bundled up inside this function.

## Function `generate_r1cs_witness()`

This function assumes that we've already set the public value `out`, and the witness value `x`. It then computes the inferred witness values for the intermediate variables `sym_1`, `y`, `sym_2`. Thus the user of the gadget never needs to worry about the intermediate variables.

## Using the gadget

In the file `src/test-gadget.cpp` we can see how the gadget it used. This file is very similar to the file in the previous section. We start as before by generating curve parameters. After this we initialize the protoboard, and allocate the variables `out`, `x` to the protoboard:

```
protoboard<FieldT> pb;
pb_variable<FieldT> out;
pb_variable<FieldT> x;

out.allocate(pb, "out");
x.allocate(pb, "x");
```

After this we specify which variables are public and which are private (in the zk-SNARK sense). This would be `out` as the only public variable and the rest as private variables. We also create a new `test_gadget`:

```
pb.set_input_sizes(1);
test_gadget<FieldT> g(pb, out, x);
```

Next generate the R1CS constraints by simply calling the corresponding function:

```
g.generate_r1cs_constraints();
```

Now we add the witness values. We add the value 35 for the public variable `out` and the value 3 for the witness variable `x`. The rest of the values will be computed inside the gadget:

```
pb.val(out) = 35;
pb.val(x) = 3;
g.generate_r1cs_witness();
```

That's it! Now we can run the Generator to generate proving and verification keys, create the proof and verify it as we did before.

# Verifying proofs on Ethereum

One of the exciting recent developments around zk-SNARKs is that it is now possible to verify a zk-SNARK proof in a smart contract on Ethereum. This opens up the possibility of private transactions and the ability to verify large computations on the blockchain.

Now that we have an example circuit, let's see how we can create a Solidity smart contract to generate proofs for that circuit on Ethereum.

## Serializing verification keys and proofs

First we need to extract the verification keys and proofs from libsnark in a way that can be consumed by Solidity smart contracts. In the file `src/util.hpp` we demonstrate how to serialize the information from the objects `r1cs_ppzksnark_verification_key` and `r1cs_ppzksnark_proof` and write that information to a file in the form of field elements that can be interpreted as `uint` types in Solidity.

We won't go into detail here about the meaning of the values `A`, `B`, `C` etc in the proof data but check out [Vitalik's blog post](https://medium.com/@VitalikButerin/zk-snarks-under-the-hood-b33151a013f6) to learn more. The main thing to illustrate is that these values are elliptic curve points and hence will be represented by two elements of the underlying field. The curve points of type `G1` has field elements that can be represented by one `uint` type, but the curve points of type `G2` has field elements that are represented by two `uint` types.

Thus each `G1` point is serialized into two integers and each `G2` point is serialized into four integers. When running the executable `./src/test-gadget` from within the build directory two files will be created: `proof_data` and `vk_data` containing the corresponding data in the form of integer values.

## Using verification keys and proofs in Solidity

We first take a look at the Solidity file `src/ethereum/contracts/Verifier.sol` which contains the verification code. This file has two important functions: `setVerifyingKey()` sets the verification key that will be used when verifying a proof and `verifyTx()` submits the proof along with the public inputs and returns `true` if the proof verifies. It is common to hardcode the verification key into the smart contract to save gas - for instance [ZoKrates](https://github.com/JacobEberhardt/ZoKrates) does this - but to simplify testing we use a setter function instead.

To see how to use the verifier smart contract from JavaScript, take a look at the test located at `src/ethereum/test/TestVerifier.js`. This file shows how to read the verification key and the proof from the files, set the verification key in the smart contract and call the smart contract to verify a proof.

Note the inputs to the function `verifyTx()` - the first inputs are the values making up the proof in the form of points of type `G1` - represented by a pair of integers, or points of type `G2` represented by a pair of integer pairs (i.e. four integers). The last input is a list of integers corresponding to the public inputs. In our case we have only one public input, the value 35 for the `out` variable which corresponds to a list with one element, `[35]`.

## The ZoKrates tool

The software library [ZoKrates](https://github.com/JacobEberhardt/ZoKrates) builds on libsnark and aims to make it a lot easier to create circuits and verify them on Ethereum by using a domain specific language and automatically creating the required smart contracts from the verification keys. You can read more about it on their [github repo](https://github.com/JacobEberhardt/ZoKrates).

# Conclusion

The libsnark zk-SNARK library is a powerful library for defining circuits, generating & verifying proofs, but it can be hard to get a sense of how to use it in practice. This tutorial aims to provide a sense of the high-level components of libsnark and how to use it concretely, as well as how to connect the proofs to Ethereum smart contracts.
