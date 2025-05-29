import init, { validate_keys, Circuit, Test } from './double_blind_web.js';

let circuit;
let test_object;

function update_key_inputs() {
  const pk = document.getElementById("public-keys");
  const dk = document.getElementById("double-blind-key");
  const sign = document.getElementById("sign");
  const data = validate_keys(pk.value, dk.value);
  if (data.user_public_key_index !== undefined) {
    const uk = document.getElementById("user-public-key");
    uk.value = pk.value.split(/\r\n|\r|\n/)[data.user_public_key_index];
  }
  const all_keys_valid = data.public_keys_valid.every(i => i);
  sign.disabled = (data.user_public_key_index === undefined) || (circuit === undefined) || !all_keys_valid;
}

function check_verify_enabled() {
  verify.disabled = (circuit === undefined)
}

function generate_circuit() {
  const make = document.getElementById("make-circuit");
  circuit = new Circuit();
  make.value = "Circuit generated"
  make.disabled = true;
  update_key_inputs();
  check_verify_enabled();
}

function generate_signature() {
  const msg = document.getElementById("message");
  const pk = document.getElementById("public-keys");
  const dk = document.getElementById("double-blind-key");
  const signature = document.getElementById("signature");
  signature.value = circuit.generate_signature(msg.value, pk.value, dk.value);
}

function verify_signature() {
  console.log("verifying...");
  const msg = document.getElementById("message");
  const pk = document.getElementById("public-keys");
  const signature = document.getElementById("signature");
  const status = document.getElementById("status");
  try {
    pk.value = circuit.read_signature(msg.value, signature.value);
    status.innerText = "Signature successfully verified!";
  } catch(error) {
    status.innerText = error;
  }
}

async function run() {
  await init();
  const pk = document.getElementById("public-keys");
  const dk = document.getElementById("double-blind-key");
  const sign = document.getElementById("sign");
  const verify = document.getElementById("verify");
  const make = document.getElementById("make-circuit");

  update_key_inputs();
  check_verify_enabled();
  dk.addEventListener('input', update_key_inputs);
  pk.addEventListener('input', update_key_inputs);
  make.addEventListener('click', generate_circuit);
  sign.addEventListener('click', generate_signature);
  verify.addEventListener('click', verify_signature);
}

run();
