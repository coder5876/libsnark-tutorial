var fs = require('fs');
var Verifier = artifacts.require("Verifier");

var vk;
var proof;

var A, B, C;
var gamma, gamma_beta_1, gamma_beta_2;
var Z;
var IC = [];

var A_g, A_h, B_g, B_h, C_g, C_h;
var H, K;

contract('Verifier', function(accounts) {
	fs.readFile("../../build/vk_data", function(err, data) {
		if(err) {
			console.log("Error reading vk_data");
		}
		vk = data.toString().replace(/\n/g, " ").split(" ");
		console.log("vk_data:");
		console.log(vk);
	});
	fs.readFile("../../build/proof_data", function(err, data) {
		if(err) {
			console.log("Error reading proof_data");
		}
		proof = data.toString().replace(/\n/g, " ").split(" ");
		console.log("proof_data:");
		console.log(proof);
	});

	it("should have vk and proof data", function() {
		assert.isAtLeast(vk.length, 24, "vk_data not correct size");
		assert.isAtLeast(proof.length, 18, "proof_data not correct size");
	});

	it("should set verifying key", function() {
		var verifier;
		
		return Verifier.deployed().then(function(instance) {
			verifier = instance;
		}).then(function() {
			A = parseG2Point(vk);
			vk = vk.slice(4);
			B = parseG1Point(vk);
			vk = vk.slice(2);
			C = parseG2Point(vk);
			vk = vk.slice(4);
			gamma = parseG2Point(vk);
			vk = vk.slice(4);
			gamma_beta_1 = parseG1Point(vk);
			vk = vk.slice(2);
			gamma_beta_2 = parseG2Point(vk);
			vk = vk.slice(4);
			Z = parseG2Point(vk);
			vk = vk.slice(4);
			while(vk != [] && vk[0] != "") {
				IC.push(parseG1Point(vk));
				vk = vk.slice(2);
			}

			return verifier.setVerifyingKey(A, B, C,
											gamma, gamma_beta_1, gamma_beta_2,
											Z,
											IC);
		}).then(function() {
			return verifier.verifyingKeySet.call();
		}).then(function(verifyingKeySet) {
			assert.equal(verifyingKeySet, true, "Verification key not set");
		});
	});

	it("should verify correct proof", function() {
		var verifier;

		return Verifier.deployed().then(function(instance) {
			verifier = instance;
		}).then(function() {
			A_g = parseG1Point(proof);
			proof = proof.slice(2);
			A_h = parseG1Point(proof);
			proof = proof.slice(2);
			B_g = parseG2Point(proof);
			proof = proof.slice(4);
			B_h = parseG1Point(proof);
			proof = proof.slice(2);
			C_g = parseG1Point(proof);
			proof = proof.slice(2);
			C_h = parseG1Point(proof);
			proof = proof.slice(2);
			H = parseG1Point(proof);
			proof = proof.slice(2);
			K = parseG1Point(proof);
			proof = proof.slice(2);

			return verifier.verifyTx.call(A_g, A_h, B_g, B_h, C_g, C_h,
										  H, K,
										  [35]);
		}).then(function(result) {
			assert.equal(result, true, "The correct proof did not verify");
		});
	});

	it("shouldn't verify incorrect proof", function() {
		var verifier;

		var wrongProof, wrongInput;

		return Verifier.deployed().then(function(instance) {
			verifier = instance;

			return verifier.verifyTx.call([0,0], A_h, B_g, B_h, C_g, C_h,
										  H, K,
										  [35]);
		}).then(function(result) {
			wrongProof = result;

			return verifier.verifyTx.call(A_g, A_h, B_g, B_h, C_g, C_h,
										  H, K,
										  [0]);
		}).then(function(result) {
			wrongInput = result;
		}).then(function() {
			assert.equal(wrongProof, false, "The incorrect proof was verified");
			assert.equal(wrongInput, false, "The incorrect input was verified");
		});
	});
});

function parseG1Point(data) {
	var X = data[0];
	var Y = data[1];
	return [X, Y];
}

function parseG2Point(data) {
	var X = [data[1], data[0]];
	var Y = [data[3], data[2]];
	return [X, Y];
}
