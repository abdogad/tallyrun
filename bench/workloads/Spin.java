// Run via the source launcher (`java Spin.java`): measures in-process javac +
// JVM startup + C2 JIT of a hot loop — the noisiest realistic judge runtime.
public class Spin {
    public static void main(String[] args) {
        long s = 0;
        for (long i = 0; i < 600_000_000L; i++) s += i % 7;
        System.out.println(s);
    }
}
