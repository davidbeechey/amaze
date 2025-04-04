//! Super hacky benchmark for android
//! Inspired by https://github.com/nirvantyagi/orca/blob/master/benches/microbenchmarks.rs

#[cfg(target_os = "android")]
use amaze::amf::{
    franking::{judge, keygen},
    two_signature::{two_frank, two_verify},
    AMFRole,
};
#[cfg(target_os = "android")]
use std::time::Instant;

#[cfg(target_os = "android")]
fn main() {
    let mut keygen_times = Vec::new();
    let mut frank_times = Vec::new();
    let mut verify_times = Vec::new();
    let mut rp_judge_times = Vec::new();
    let mut sp_judge_times = Vec::new();

    // Store the verify and judge results in an array so they are not optimized out
    let mut verify_results = Vec::new();
    let mut rp_judge_results = Vec::new();
    let mut sp_judge_results = Vec::new();

    // 0. Initialize a Sender
    let (sender_public_key, sender_secret_key) = keygen(AMFRole::Sender);
    // 1. Initialize RP and SP (judges)
    let (rp_public_key, rp_secret_key) = keygen(AMFRole::Judge);
    let (sp_public_key, sp_secret_key) = keygen(AMFRole::Judge);

    // BENCH 0: Bench keygen
    let mut start: Instant;
    for _ in 0..10_000 {
        // 2. Initialize a Recipient
        start = Instant::now();
        let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
        keygen_times.push(start.elapsed().as_micros());

        // 3. Initialize a message
        let message = b"hello world!";

        // 4. Frank the message
        start = Instant::now();
        let (amf_signature_1, amf_signature_2) = two_frank(
            sender_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
        );
        frank_times.push(start.elapsed().as_micros());

        // 5. Verify the message
        start = Instant::now();
        let verify_result = two_verify(
            recipient_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            sp_public_key,
            message,
            amf_signature_1,
            amf_signature_2,
        );
        verify_times.push(start.elapsed().as_micros());
        verify_results.push(verify_result);

        // 5. Judge the message (RP)
        start = Instant::now();
        let rp_judge_result = judge(
            rp_secret_key,
            sender_public_key,
            recipient_public_key,
            rp_public_key,
            message,
            amf_signature_1,
        );
        rp_judge_times.push(start.elapsed().as_micros());
        rp_judge_results.push(rp_judge_result);

        // 6. Judge the message (SP)
        start = Instant::now();
        let sp_judge_result = judge(
            sp_secret_key,
            sender_public_key,
            recipient_public_key,
            sp_public_key,
            message,
            amf_signature_2,
        );
        sp_judge_times.push(start.elapsed().as_micros());
        sp_judge_results.push(sp_judge_result);
    }

    print_summary_stats("keygen", keygen_times);
    print_summary_stats("frank", frank_times);
    print_summary_stats("verify", verify_times);
    print_summary_stats("rp_judge", rp_judge_times);
    print_summary_stats("sp_judge", sp_judge_times);

    let all_verify_succeeded = verify_results.iter().all(|&item| item == true);
    let all_rp_judge_succeeded = rp_judge_results.iter().all(|&item| item == true);
    let all_sp_judge_succeeded = sp_judge_results.iter().all(|&item| item == true);

    println!("\nAll verify succeeded: {}", all_verify_succeeded);
    println!("All rp_judge succeeded: {}", all_rp_judge_succeeded);
    println!("All sp_judge succeeded: {}", all_sp_judge_succeeded);
}

#[cfg(target_os = "android")]
fn print_summary_stats(name: &str, times: Vec<u128>) {
    let sum = times.iter().sum::<u128>() as u128;
    println!(
        "{}\t\tmean: {} us\n",
        name.to_uppercase(),
        sum / (times.len() as u128)
    )
}

#[cfg(not(target_os = "android"))]
fn main() {
    eprintln!(
        "This benchmark is exclusively for android. On more featured platforms, use `franking.rs`."
    )
}
