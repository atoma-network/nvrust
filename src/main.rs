use nvrust::{call_fetch_attestation_report, fetch_attestation_report};
use std::env;

fn main() {
    // Create a sample nonce (this should be a properly generated nonce in production)
    let nonce = vec![0u8; 32]; // 32 bytes of zeros as a sample

    // Get GPU index from command line args or default to 0
    let args: Vec<String> = env::args().collect();
    let gpu_index = if args.len() > 1 {
        args[1].parse::<usize>().unwrap_or(0)
    } else {
        0 // Default to first GPU
    };

    println!("Fetching attestation report for GPU {}", gpu_index);

    // Call the main function
    match fetch_attestation_report(gpu_index, nonce) {
        Ok(report) => {
            println!("Successfully fetched attestation report!");
            println!("Report size: {} bytes", report.len());

            // Print first few bytes as hex for verification
            println!("First 16 bytes: {:02X?}", &report[..16.min(report.len())]);
        }
        Err(e) => {
            eprintln!("Error fetching attestation report: {}", e);
        }
    }

    // Alternative approach using the direct method call
    // Uncomment to try this approach
    /*
    match call_fetch_attestation_report(gpu_index, nonce) {
        Ok(report) => {
            println!("Successfully fetched attestation report using direct method call!");
            println!("Report size: {} bytes", report.len());
        },
        Err(e) => {
            eprintln!("Error fetching attestation report (direct call): {}", e);
        }
    }
    */
}
