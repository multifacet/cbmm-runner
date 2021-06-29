fn main() {
    let info = std::fs::read_to_string("/proc/buddyinfo")
        .unwrap()
        .lines()
        .filter(|line| line.contains("Normal"))
        .map(|line| {
            line.split_whitespace()
                .skip(4)
                .map(str::trim)
                .map(|v| v.parse::<usize>().unwrap())
                .enumerate()
                .map(|(i, v)| v * 2usize.pow(i as u32))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let n = info[0].len();
    let combined = (0..n)
        .map(|i| info.iter().map(|v| v[i]).sum())
        .collect::<Vec<usize>>();

    println!("Free list sizes: {:?}", combined);

    let total: usize = combined.iter().sum();
    let fragmented: usize = combined.iter().take(9).sum();

    println!(
        "{} ({}GB) / {} ({}GB) = {:.1}% fragmented",
        fragmented,
        fragmented >> (30 - 12),
        total,
        total >> (30 - 12),
        (fragmented as f64) / (total as f64) * 100.0
    );
}
