use super::franking::{frank, verify, AMFPublicKey, AMFSecretKey, AMFSignature};

pub use super::franking::{judge, keygen, AMFRole};

pub fn two_frank(
    sender_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    recipient_public_key: AMFPublicKey,
    rp_public_key: AMFPublicKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
) -> (AMFSignature, AMFSignature) {
    (
        frank(
            sender_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            message,
        ),
        frank(
            sender_secret_key,
            sender_public_key,
            recipient_public_key,
            sp_public_key,
            message,
        ),
    )
}

pub fn two_verify(
    recipient_secret_key: AMFSecretKey,
    sender_public_key: AMFPublicKey,
    recipient_public_key: AMFPublicKey,
    rp_public_key: AMFPublicKey,
    sp_public_key: AMFPublicKey,
    message: &[u8],
    amf_signature: AMFSignature,
    amf_signature_2: AMFSignature,
) -> bool {
    verify(
        recipient_secret_key,
        sender_public_key,
        recipient_public_key,
        rp_public_key,
        message,
        amf_signature,
    ) && verify(
        recipient_secret_key,
        sender_public_key,
        recipient_public_key,
        sp_public_key,
        message,
        amf_signature_2,
    )
}

#[cfg(test)]
mod tests {
    use crate::amf::two_signature::{judge, keygen, two_frank, two_verify, AMFRole};

    #[test]
    fn test_franking() {
        // 0. Initialize a Sender
        let (sender_public_key, sender_secret_key) = keygen(AMFRole::Sender);
        // 1. Initialize a Recipient
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        // 2. Initialize a Judge
        let (rp_public_key, rp_secret_key) = keygen(AMFRole::Judge);
        let (sp_public_key, sp_secret_key) = keygen(AMFRole::Judge);

        // 3. Initialize a message
        let message = b"hello world!";

        // 4. Frank the message
        let (amf_signature, amf_signature_2) = two_frank(
            sender_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
        );

        // 5. Verify the message
        let verification_result = two_verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature,
            amf_signature_2,
        );
        assert!(verification_result);

        // 6. Judge the message
        let rp_judge_result = judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            message,
            amf_signature,
        );
        assert!(rp_judge_result);

        let sp_judge_result = judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            sp_public_key,
            message,
            amf_signature_2,
        );
        assert!(sp_judge_result);
    }
}
