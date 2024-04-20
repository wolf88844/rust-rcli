use anyhow::Result;
use clap::Parser;
use template::{process_csv, Opts, SubCommand};

fn main() ->Result<()>{
    let opts = Opts::parse();
    match opts.cmd{
        SubCommand::Csv(opts)=>process_csv(&opts.input,&opts.output)?,
        
    }
    Ok(())
}
