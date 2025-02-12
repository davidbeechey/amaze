use amaze::amf::{franking::*, AMFRole};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("amf");
    group.significance_level(0.1).sample_size(1000);

    // 0. Initialize a Sender
    let (sender_public_key, sender_secret_key) = keygen(AMFRole::Sender);
    // 1. Initialize a Recipient
    let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
    // 2. Initialize a Sender Platform's Judge
    let (rp_public_key, rp_secret_key) = keygen(AMFRole::ReceiverPlatformJudge);
    // 3. Initialize a Recipient Platform's Judge
    let (sp_public_key, sp_secret_key) = keygen(AMFRole::SenderPlatformJudge);

    // 3. Initialize a message
    let message = b"hello world!";

    // 4. Frank the message
    let amf_signature = frank(
        sender_secret_key,
        sender_public_key,
        recipient_public_key,
        rp_public_key,
        sp_public_key,
        message,
    );

    group.bench_function("keygen", |b| b.iter(|| keygen(AMFRole::Sender)));
    group.bench_function("franking", |b| {
        b.iter(|| {
            frank(
                black_box(sender_secret_key),
                black_box(sender_public_key),
                black_box(recipient_public_key),
                black_box(rp_public_key),
                black_box(sp_public_key),
                black_box(message),
            )
        })
    });
    group.bench_function("verifying", |b| {
        b.iter(|| {
            verify(
                black_box(recipient_secret_key),
                black_box(sender_public_key),
                black_box(recipient_public_key),
                black_box(rp_public_key),
                black_box(sp_public_key),
                black_box(message),
                black_box(amf_signature),
            )
        })
    });
    group.bench_function("rp_judge", |b| {
        b.iter(|| {
            rp_judge(
                black_box(rp_secret_key),
                black_box(sender_public_key),
                black_box(recipient_public_key),
                black_box(rp_public_key),
                black_box(sp_public_key),
                black_box(message),
                black_box(amf_signature),
            )
        })
    });
    group.bench_function("sp_judge", |b| {
        b.iter(|| {
            sp_judge(
                black_box(sp_secret_key),
                black_box(sender_public_key),
                black_box(recipient_public_key),
                black_box(rp_public_key),
                black_box(sp_public_key),
                black_box(message),
                black_box(amf_signature),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
