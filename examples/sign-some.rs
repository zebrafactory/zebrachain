use zebrachain::secretseed::Seed;

fn main() {
    let initial_entropy = [69; 32];
    let new_entropy = [42; 32];
    let mut seed = Seed::create(&initial_entropy);
    println!("{} 0", seed.secret);
    println!("{} 1", seed.next_secret);
    for i in 0..256 {
        let next = seed.advance(&new_entropy);
        seed.commit(next);
        println!("{} {}", seed.next_secret, i + 2);
    }
}
