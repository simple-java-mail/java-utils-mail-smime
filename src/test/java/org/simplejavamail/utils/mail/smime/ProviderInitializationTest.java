package org.simplejavamail.utils.mail.smime;

import jakarta.activation.CommandInfo;
import jakarta.activation.CommandMap;
import jakarta.activation.DataContentHandler;
import jakarta.activation.MailcapCommandMap;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class ProviderInitializationTest {
    @ParameterizedTest
    @ValueSource(strings = {"keystore-first", "provider-preinstalled", "custom-command-map"})
    void initializationWorksInAFreshJvm(String scenario) throws Exception {
        String javaExecutable = new File(System.getProperty("java.home"), "bin/java").getAbsolutePath();
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        Process process = new ProcessBuilder(javaExecutable, "-cp", classpath, Probe.class.getName(), scenario)
                .redirectErrorStream(true).start();
        try {
            assertThat(process.waitFor(30, TimeUnit.SECONDS)).as("child JVM finished").isTrue();
            String output = new String(SmimeTestSupport.read(process.getInputStream()), java.nio.charset.StandardCharsets.UTF_8);
            assertThat(process.exitValue()).as(output).isZero();
        } finally {
            process.destroyForcibly();
        }
    }

    /** Separate process avoids test-order dependence and modifications to the test runner's providers. */
    public static class Probe {
        public static void main(String[] args) throws Exception {
            Security.removeProvider("BC");
            if (args[0].equals("keystore-first")) {
                if (new SmimeKeyStore(null, null).size() != 0) {
                    throw new AssertionError("Expected empty PKCS12 store");
                }
            } else if (args[0].equals("provider-preinstalled")) {
                BouncyCastleProvider provider = new BouncyCastleProvider();
                Security.addProvider(provider);
                RecordingMailcap map = new RecordingMailcap();
                CommandMap.setDefaultCommandMap(map);
                Class.forName(SmimeUtil.class.getName());
                if (Security.getProvider("BC") != provider || map.registrations.size() != 5) {
                    throw new AssertionError("Existing provider must retain its identity and MIME handlers must still be registered");
                }
            } else {
                CommandMap custom = new CommandMap() {
                    @Override public CommandInfo[] getPreferredCommands(String type) { return new CommandInfo[0]; }
                    @Override public CommandInfo[] getAllCommands(String type) { return new CommandInfo[0]; }
                    @Override public CommandInfo getCommand(String type, String command) { return null; }
                    @Override public DataContentHandler createDataContentHandler(String type) { return null; }
                };
                CommandMap.setDefaultCommandMap(custom);
                Class.forName(SmimeUtil.class.getName());
                if (CommandMap.getDefaultCommandMap() != custom) {
                    throw new AssertionError("Application command map must be retained");
                }
            }
        }
    }

    private static class RecordingMailcap extends MailcapCommandMap {
        final List<String> registrations = new ArrayList<>();
        @Override public synchronized void addMailcap(String mailcap) {
            registrations.add(mailcap);
            super.addMailcap(mailcap);
        }
    }
}
