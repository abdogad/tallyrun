// Run with the source launcher (`java Spin.java`), so the count includes
// in-process javac, JVM startup and the C2 JIT of a hot loop. This is the
// noisiest runtime a judge realistically sees.
public class Spin {
    public static void main(String[] args) {
        long s = 0;
        for (long i = 0; i < 600_000_000L; i++) s += i % 7;
        System.out.println(s);
    }
}
