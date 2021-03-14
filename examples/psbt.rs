extern crate bitcoin;

use bitcoin::secp256k1::{Message, Secp256k1, SerializedSignature};

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::{OutPoint, SigHashType, TxIn, TxOut};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hash_types::Txid;
use bitcoin::hashes::hex::FromHex;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt;
use bitcoin::Transaction;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    // Create a base transaction with a consumable UTXO
    // The UTXO require only one signature

    let privkey: PrivateKey =
        PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D")?;
    let pubkey = PublicKey::from_private_key(&secp, &privkey);

    let base_tx = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_hex(
                    "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389",
                )?,
                vout: 1,
            },
            script_sig: Script::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985")?,
            sequence: 4294967295,
            witness: vec![Vec::from_hex(
                "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105",
            )?],
        }],
        output: vec![TxOut {
            value: 10_000_000,
            script_pubkey: Script::new_v0_wpkh(&pubkey.wpubkey_hash().unwrap()),
        }],
    };

    // Create a transaction spending the base_tx output
    // base_tx output can be spend with a single signature
    // Transaction creates a new 2-of-2 multisig UTXO

    let privkey_a: PrivateKey =
        PrivateKey::from_wif("L2ADhiVUo77CB7vR3BiUca9KwzRiW2ds5vPh7qUUiBr5iXmCYhQi")?;
    let pubkey_a = PublicKey::from_private_key(&secp, &privkey_a);

    let privkey_b: PrivateKey =
        PrivateKey::from_wif("L4TsNhA4Aiwq3Lqjkmrrg2fBZmNfcuDqY5KSFdRx9gnyY3R8xvjf")?;
    let pubkey_b = PublicKey::from_private_key(&secp, &privkey_b);

    let multisig_script = Builder::new()
        .push_opcode(opcodes::all::OP_PUSHNUM_2)
        .push_key(&pubkey_a)
        .push_key(&pubkey_b)
        .push_opcode(opcodes::all::OP_PUSHNUM_2)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script();

    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: base_tx.txid(),
                vout: 0,
            },
            script_sig: Script::default(),
            sequence: 0,
            witness: vec![],
        }],
        output: vec![TxOut {
            value: 10_000_000,
            script_pubkey: multisig_script.to_v0_p2wsh(),
        }],
    };

    // Create the PSBT structure and sign the output
    //
    // this correspond to the 'creator' role as defined in BIP 0174.
    let mut psbt = psbt::PartiallySignedTransaction::from_unsigned_tx(tx.clone())?;

    // Update the PSBT to include per-inputs, per-outputs maps data
    //
    // this correspond to the `updater` role as defined in BIP 0174.
    //
    // update per-input, per-output maps:
    //  - set the input UTXOs we spend from
    //  - set the input signatures hash type
    //  - set the outputs witness script as the multisig script
    {
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 10_000_000,
            script_pubkey: Script::new_v0_wpkh(&pubkey.wpubkey_hash().unwrap()),
        });
        psbt.inputs[0].sighash_type = Some(SigHashType::All);
        psbt.outputs[0].witness_script = Some(multisig_script.clone());
    }

    // send over the network
    psbt = deserialize(&serialize(&psbt))?;

    // Sign the input based on provided data inside the PSBT, if amount, keys, etc. are correct the
    // signer can produce a valid partial signature
    //
    // this correspond to the `signer` role as defined in BIP 0174.
    //
    // validate the inputs:
    //  - check if witness utxo is set and is a segwit p2wpkh with the correct public key
    //  - check that the public key hash correspond to the public key
    //  - check the signature hash type correspond to ALL
    {
        let tx_out = psbt.inputs[0].witness_utxo.clone().unwrap();
        assert_eq!(tx_out.value, 10_000_000);
        assert!(tx_out.script_pubkey.is_v0_p2wpkh());
        let pubkey_hash = pubkey.wpubkey_hash().unwrap();
        assert_eq!(pubkey_hash[..], tx_out.script_pubkey.as_bytes()[2..]);
        assert_eq!(psbt.inputs[0].sighash_type, Some(SigHashType::All));
    }
    // check that the output UTXO is the one expected:
    {
        assert!(psbt.outputs[0].witness_script.is_some());
        assert_eq!(
            psbt.outputs[0].witness_script.clone().unwrap(),
            multisig_script
        );
        assert_eq!(psbt.global.unsigned_tx.output[0].value, 10_000_000);
        assert_eq!(
            psbt.global.unsigned_tx.output[0].script_pubkey,
            multisig_script.to_v0_p2wsh()
        );
    }
    // sign and set the partial signature:
    {
        let unsigned_tx = psbt.global.unsigned_tx.clone();
        let input = psbt.inputs[0].clone();
        let sig = sign_input(&secp, &unsigned_tx, 0, input, &privkey.key);
        // save the signature on the per-input map
        psbt.inputs[0].partial_sigs.insert(pubkey, sig.to_vec());
    }

    // send over the network
    psbt = deserialize(&serialize(&psbt))?;

    // When every signer produced their partial signatures, a finalizer can aggregate them into the
    // `scriptSig` and/or `scriptWitness`
    //
    // this correspond to the `finalizer` role as defined in BIP 0174.
    {
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        let sig = psbt.inputs[0].partial_sigs.get(&pubkey).unwrap().clone();
        psbt.inputs[0].final_script_witness = Some(vec![sig.to_vec(), pubkey.to_bytes()]);
    }

    // send over the network
    psbt = deserialize(&serialize(&psbt))?;

    // After finalizing the PSBT an extractor can produce the network compatible version of the
    // transaction
    //
    // this correspond to the `extractor` role as defined in BIP 0174.
    let _fully_signed_tx = psbt.extract_tx();

    // Create another transaction based on the previous unfinalaize transaction
    // this transaction's input requires two signatures

    let multisig_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: tx.txid(),
                vout: 0,
            },
            script_sig: Script::default(),
            sequence: 0,
            witness: vec![],
        }],
        output: vec![ /* we omit outputs here */ ],
    };

    let mut psbt = psbt::PartiallySignedTransaction::from_unsigned_tx(multisig_tx.clone())?;

    // Update the PSBT to include per-inputs, per-outputs maps data
    //
    // this correspond to the `updater` role as defined in BIP 0174.
    //
    // update per-input, per-output maps:
    //  - set the input UTXOs we spend from
    //  - set the input signatures hash type
    {
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 10_000_000,
            script_pubkey: multisig_script.to_v0_p2wsh(),
        });
        psbt.inputs[0].sighash_type = Some(SigHashType::All);
        psbt.inputs[0].witness_script = Some(multisig_script.clone());
    }

    // serialize and send over the network
    let psbt = serialize(&psbt);

    // Each participant sign the input based on provided data inside the PSBT, if amount, keys,
    // etc. are correct the signer can produce a valid partial signature
    //
    // this correspond to the `signer` role as defined in BIP 0174.

    // ...we skip the validation process to simplify the example...

    // Alice signs and set the partial signature:
    let alice_psbt = {
        let mut alice_psbt: psbt::PartiallySignedTransaction = deserialize(&psbt.clone())?;
        let unsigned_tx = alice_psbt.global.unsigned_tx.clone();
        let input = alice_psbt.inputs[0].clone();
        let sig = sign_input(&secp, &unsigned_tx, 0, input, &privkey_a.key);
        // save the signature on the per-input map
        alice_psbt.inputs[0]
            .partial_sigs
            .insert(pubkey_a, sig.to_vec());
        serialize(&alice_psbt)
    };
    // Bob signs and set the partial signature
    let bob_psbt = {
        let mut bob_psbt: psbt::PartiallySignedTransaction = deserialize(&psbt.clone())?;
        let unsigned_tx = bob_psbt.global.unsigned_tx.clone();
        let input = bob_psbt.inputs[0].clone();
        let sig = sign_input(&secp, &unsigned_tx, 0, input, &privkey_b.key);
        // save the signature on the per-input map
        bob_psbt.inputs[0]
            .partial_sigs
            .insert(pubkey_b, sig.to_vec());
        serialize(&bob_psbt)
    };
    // merge both PSBT
    let mut psbt: psbt::PartiallySignedTransaction = deserialize(&alice_psbt)?;
    psbt.merge(deserialize(&bob_psbt)?)?;

    // When every signer produced their partial signatures, a finalizer can aggregate them into the
    // `scriptSig` and/or `scriptWitness`
    //
    // this correspond to the `finalizer` role as defined in BIP 0174.
    {
        // ...we skip validation...
        let sig_a = psbt.inputs[0].partial_sigs.get(&pubkey_a).unwrap().clone();
        let sig_b = psbt.inputs[0].partial_sigs.get(&pubkey_b).unwrap().clone();
        psbt.inputs[0].final_script_witness = Some(vec![
            vec![0],
            sig_b.to_vec(),
            sig_a.to_vec(),
            multisig_script.to_bytes(),
        ]);
    }

    // After finalizing the PSBT an extractor can produce the network compatible version of the
    // transaction
    //
    // this correspond to the `extractor` role as defined in BIP 0174.
    let _fully_signed_tx = psbt.extract_tx();

    Ok(())
}

fn sign_input(
    ctx: &Secp256k1<bitcoin::secp256k1::All>,
    unsigned_tx: &Transaction,
    index: usize,
    input: psbt::Input,
    key: &bitcoin::secp256k1::SecretKey,
) -> SerializedSignature {
    let sighash = unsigned_tx.signature_hash(
        index,
        &input.witness_utxo.unwrap().script_pubkey,
        input.sighash_type.unwrap().as_u32(),
    );
    let message = Message::from_slice(&sighash[..]).expect("32 bytes");
    let mut sig = ctx.sign(&message, &key);
    sig.normalize_s();
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(ctx, &key);
    assert!(ctx.verify(&message, &sig, &pubkey).is_ok());
    sig.serialize_der()
}
