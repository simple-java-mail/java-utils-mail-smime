package org.simplejavamail.utils.mail.smime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class DocumentationExamplesTest {
    @TempDir Path directory;

    @Test
    void readmeJavaExamplesCompileAgainstTheActualPublicApi() throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertThat(compiler).as("Run the suite with a JDK").isNotNull();
        String readme = new String(Files.readAllBytes(Paths.get("README.md")), StandardCharsets.UTF_8);
        Matcher examples = Pattern.compile("```java\\R(.*?)```", Pattern.DOTALL).matcher(readme);
        int count = 0;
        try (StandardJavaFileManager files = compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            while (examples.find()) {
                String source = examples.group(1);
                Matcher declaration = Pattern.compile("public final class (\\w+)").matcher(source);
                assertThat(declaration.find()).as("Each example is a complete, copyable class").isTrue();
                Path file = directory.resolve(declaration.group(1) + ".java");
                Files.write(file, source.getBytes(StandardCharsets.UTF_8));
                String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
                Boolean compiled = compiler.getTask(null, files, null,
                        Arrays.asList("-source", "8", "-target", "8", "-Xlint:-options", "-classpath", classpath, "-d", directory.toString()),
                        null, files.getJavaFileObjectsFromFiles(Collections.singletonList(file.toFile()))).call();
                assertThat(compiled).as(declaration.group(1)).isTrue();
                count++;
            }
        }
        assertThat(count).as("README contains Java examples to validate").isPositive();
    }
}
