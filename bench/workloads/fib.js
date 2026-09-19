// V8 JIT workload. The hot loop moves through Ignition, Sparkplug and
// Maglev/TurboFan during the run, so the count includes JIT compilation.
let s = 0;
for (let i = 0; i < 300_000_000; i++) s += i % 7;
console.log(s);
