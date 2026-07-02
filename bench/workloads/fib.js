// V8 JIT workload: hot numeric loop, tiers through Ignition -> Sparkplug ->
// Maglev/TurboFan during the run, so instruction count includes JIT work.
let s = 0;
for (let i = 0; i < 300_000_000; i++) s += i % 7;
console.log(s);
