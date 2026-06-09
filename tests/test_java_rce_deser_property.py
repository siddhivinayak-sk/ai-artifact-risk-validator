"""Property-based tests for JavaAnalyzer RCE and Deserialization detection.

Feature: extended-mcp-scanning
- Property 2: RCE Pattern Detection Across Languages (Java subset)
- Property 4: Unsafe Deserialization Detection Across Languages (Java subset)

**Validates: Requirements 3.2, 3.3**

Property 2 (Java subset):
- For any Java/Kotlin source file containing Runtime.exec(), ProcessBuilder, or
  ScriptEngine.eval(), the JavaAnalyzer SHALL produce at least one ScanFinding
  with id="MCP-S1".

Property 4 (Java subset):
- For any Java/Kotlin source file containing ObjectInputStream.readObject(),
  XMLDecoder, XStream.fromXML(), or Kryo.readObject(), the JavaAnalyzer SHALL
  produce at least one ScanFinding with id="MCP-S8".
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from ai_artifact_risk_validator.models.enums import ArtifactType
from ai_artifact_risk_validator.scanners.java_analyzer import JavaAnalyzer

# --- Strategies for generating Java/Kotlin code snippets ---

# Strategy for random valid Java identifiers
java_identifier = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz",
    min_size=3,
    max_size=12,
).map(lambda s: s if s[0].isalpha() else "cls" + s)

# Strategy for random Java class names (PascalCase)
java_class_name = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz",
    min_size=3,
    max_size=10,
).map(lambda s: s.capitalize() if s[0].isalpha() else "Cls" + s)

# Strategy for random method names
java_method_name = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz",
    min_size=3,
    max_size=10,
).map(lambda s: s if s[0].isalpha() else "run" + s)


# --- RCE Pattern Strategies ---


@st.composite
def java_runtime_exec_code(draw: st.DrawFn) -> str:
    """Generate Java code containing Runtime.exec() usage."""
    class_name = draw(java_class_name)
    method_name = draw(java_method_name)
    param_name = draw(java_identifier)

    variant = draw(
        st.sampled_from(
            [
                # Runtime.getRuntime().exec() with variable
                f"""import java.io.*;

public class {class_name} {{
    public void {method_name}(String {param_name}) throws IOException {{
        Runtime.getRuntime().exec({param_name});
    }}
}}
""",
                # Runtime.getRuntime().exec() with string literal
                f"""import java.io.*;

public class {class_name} {{
    public void {method_name}() throws IOException {{
        Process proc = Runtime.getRuntime().exec("ls -la");
        proc.waitFor();
    }}
}}
""",
                # Runtime.getRuntime().exec() with array
                f"""import java.io.*;

public class {class_name} {{
    public void {method_name}(String {param_name}) throws IOException {{
        String[] cmd = {{"sh", "-c", {param_name}}};
        Runtime.getRuntime().exec(cmd);
    }}
}}
""",
                # Kotlin style Runtime.exec
                f"""package com.example

class {class_name} {{
    fun {method_name}({param_name}: String) {{
        Runtime.getRuntime().exec({param_name})
    }}
}}
""",
            ]
        )
    )
    return variant


@st.composite
def java_process_builder_code(draw: st.DrawFn) -> str:
    """Generate Java code containing ProcessBuilder usage."""
    class_name = draw(java_class_name)
    method_name = draw(java_method_name)
    param_name = draw(java_identifier)

    variant = draw(
        st.sampled_from(
            [
                # ProcessBuilder with variable args
                f"""import java.io.*;

public class {class_name} {{
    public Process {method_name}(String {param_name}) throws IOException {{
        ProcessBuilder pb = new ProcessBuilder({param_name});
        return pb.start();
    }}
}}
""",
                # ProcessBuilder with list
                f"""import java.io.*;
import java.util.*;

public class {class_name} {{
    public void {method_name}(List<String> {param_name}) throws IOException {{
        ProcessBuilder pb = new ProcessBuilder({param_name});
        pb.redirectErrorStream(true);
        pb.start();
    }}
}}
""",
                # ProcessBuilder with string array
                f"""import java.io.*;

public class {class_name} {{
    public void {method_name}() throws IOException {{
        new ProcessBuilder("bash", "-c", "echo hello").start();
    }}
}}
""",
                # Kotlin style ProcessBuilder
                f"""package com.example

class {class_name} {{
    fun {method_name}({param_name}: String) {{
        val process = ProcessBuilder({param_name}).start()
        process.waitFor()
    }}
}}
""",
            ]
        )
    )
    return variant


@st.composite
def java_script_engine_eval_code(draw: st.DrawFn) -> str:
    """Generate Java code containing ScriptEngine.eval() usage."""
    class_name = draw(java_class_name)
    method_name = draw(java_method_name)
    param_name = draw(java_identifier)

    variant = draw(
        st.sampled_from(
            [
                # ScriptEngine with variable eval
                f"""import javax.script.*;

public class {class_name} {{
    public Object {method_name}(String {param_name}) throws ScriptException {{
        ScriptEngineManager mgr = new ScriptEngineManager();
        ScriptEngine engine = mgr.getEngineByName("js");
        return engine.eval({param_name});
    }}
}}
""",
                # ScriptEngine with inline script
                f"""import javax.script.*;

public class {class_name} {{
    public Object {method_name}() throws ScriptException {{
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        return engine.eval("print('hello')");
    }}
}}
""",
                # ScriptEngine with named variable
                f"""import javax.script.*;

public class {class_name} {{
    private final ScriptEngine scriptEngine;

    public {class_name}() {{
        scriptEngine = new ScriptEngineManager().getEngineByName("js");
    }}

    public Object {method_name}(String {param_name}) throws ScriptException {{
        return scriptEngine.eval({param_name});
    }}
}}
""",
                # Kotlin style ScriptEngine
                f"""package com.example

import javax.script.ScriptEngineManager

class {class_name} {{
    fun {method_name}({param_name}: String): Any? {{
        val engine = ScriptEngineManager().getEngineByName("js")
        return engine.eval({param_name})
    }}
}}
""",
            ]
        )
    )
    return variant


# --- Deserialization Pattern Strategies ---


@st.composite
def java_object_input_stream_code(draw: st.DrawFn) -> str:
    """Generate Java code containing ObjectInputStream.readObject() usage."""
    class_name = draw(java_class_name)
    method_name = draw(java_method_name)
    param_name = draw(java_identifier)

    variant = draw(
        st.sampled_from(
            [
                # ObjectInputStream with readObject on same line
                f"""import java.io.*;

public class {class_name} {{
    public Object {method_name}(InputStream {param_name}) throws Exception {{
        ObjectInputStream ois = new ObjectInputStream({param_name});
        return ois.readObject();
    }}
}}
""",
                # new ObjectInputStream construction
                f"""import java.io.*;

public class {class_name} {{
    public Object {method_name}(byte[] data) throws Exception {{
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }}
}}
""",
                # Inline readObject on same expression
                f"""import java.io.*;

public class {class_name} {{
    public Object {method_name}(InputStream {param_name}) throws Exception {{
        return new ObjectInputStream({param_name}).readObject();
    }}
}}
""",
                # Kotlin style using new keyword pattern for detection
                f"""package com.example

import java.io.*

class {class_name} {{
    fun {method_name}({param_name}: InputStream): Any? {{
        val obj = ObjectInputStream({param_name}).readObject()
        return obj
    }}
}}
""",
            ]
        )
    )
    return variant


@st.composite
def java_xml_decoder_code(draw: st.DrawFn) -> str:
    """Generate Java code containing XMLDecoder usage."""
    class_name = draw(java_class_name)
    method_name = draw(java_method_name)
    param_name = draw(java_identifier)

    variant = draw(
        st.sampled_from(
            [
                # XMLDecoder basic usage
                f"""import java.beans.XMLDecoder;
import java.io.*;

public class {class_name} {{
    public Object {method_name}(InputStream {param_name}) {{
        XMLDecoder decoder = new XMLDecoder({param_name});
        Object result = decoder.readObject();
        decoder.close();
        return result;
    }}
}}
""",
                # XMLDecoder with BufferedInputStream
                f"""import java.beans.XMLDecoder;
import java.io.*;

public class {class_name} {{
    public Object {method_name}(byte[] data) {{
        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(
            new ByteArrayInputStream(data)));
        return decoder.readObject();
    }}
}}
""",
                # Kotlin style
                f"""package com.example

import java.beans.XMLDecoder
import java.io.InputStream

class {class_name} {{
    fun {method_name}({param_name}: InputStream): Any? {{
        val decoder = XMLDecoder({param_name})
        return decoder.readObject()
    }}
}}
""",
            ]
        )
    )
    return variant


@st.composite
def java_xstream_code(draw: st.DrawFn) -> str:
    """Generate Java code containing XStream.fromXML() usage."""
    class_name = draw(java_class_name)
    method_name = draw(java_method_name)
    param_name = draw(java_identifier)

    variant = draw(
        st.sampled_from(
            [
                # XStream.fromXML with variable
                f"""import com.thoughtworks.xstream.XStream;

public class {class_name} {{
    public Object {method_name}(String {param_name}) {{
        XStream xstream = new XStream();
        return xstream.fromXML({param_name});
    }}
}}
""",
                # XStream with reader
                f"""import com.thoughtworks.xstream.XStream;
import java.io.Reader;

public class {class_name} {{
    private final XStream xstream = new XStream();

    public Object {method_name}(Reader {param_name}) {{
        return xstream.fromXML({param_name});
    }}
}}
""",
                # Kotlin style
                f"""package com.example

import com.thoughtworks.xstream.XStream

class {class_name} {{
    fun {method_name}({param_name}: String): Any? {{
        val xstream = XStream()
        return xstream.fromXML({param_name})
    }}
}}
""",
            ]
        )
    )
    return variant


@st.composite
def java_kryo_code(draw: st.DrawFn) -> str:
    """Generate Java code containing Kryo.readObject() usage."""
    class_name = draw(java_class_name)
    method_name = draw(java_method_name)
    param_name = draw(java_identifier)

    variant = draw(
        st.sampled_from(
            [
                # Kryo.readObject with Input
                f"""import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;

public class {class_name} {{
    public Object {method_name}(byte[] {param_name}) {{
        Kryo kryo = new Kryo();
        Input input = new Input({param_name});
        return kryo.readObject(input, Object.class);
    }}
}}
""",
                # Kryo with named instance
                f"""import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;

public class {class_name} {{
    private final Kryo kryo = new Kryo();

    public Object {method_name}(Input {param_name}) {{
        return kryo.readObject({param_name}, String.class);
    }}
}}
""",
                # Kotlin style
                f"""package com.example

import com.esotericsoftware.kryo.Kryo
import com.esotericsoftware.kryo.io.Input

class {class_name} {{
    fun {method_name}({param_name}: ByteArray): Any? {{
        val kryo = Kryo()
        val input = Input({param_name})
        return kryo.readObject(input, Any::class.java)
    }}
}}
""",
            ]
        )
    )
    return variant


# --- Property Tests ---


class TestJavaRCEPatternDetection:
    """Property 2 (Java subset): RCE Pattern Detection.

    Feature: extended-mcp-scanning, Property 2: RCE Pattern Detection Across Languages (Java subset)

    **Validates: Requirements 3.2**
    """

    analyzer = JavaAnalyzer()

    @given(code=java_runtime_exec_code())
    @settings(max_examples=100)
    def test_runtime_exec_detected_as_mcp_s1(self, code: str) -> None:
        """For any Java/Kotlin source file containing Runtime.exec(),
        the JavaAnalyzer SHALL produce at least one ScanFinding with id="MCP-S1"."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main/java/Server.java",
        )

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for Runtime.exec() code, "
            f"got {len(mcp_s1_findings)}. Code:\n{code}"
        )

    @given(code=java_process_builder_code())
    @settings(max_examples=100)
    def test_process_builder_detected_as_mcp_s1(self, code: str) -> None:
        """For any Java/Kotlin source file containing ProcessBuilder,
        the JavaAnalyzer SHALL produce at least one ScanFinding with id="MCP-S1"."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main/java/Service.java",
        )

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for ProcessBuilder code, "
            f"got {len(mcp_s1_findings)}. Code:\n{code}"
        )

    @given(code=java_script_engine_eval_code())
    @settings(max_examples=100)
    def test_script_engine_eval_detected_as_mcp_s1(self, code: str) -> None:
        """For any Java/Kotlin source file containing ScriptEngine.eval(),
        the JavaAnalyzer SHALL produce at least one ScanFinding with id="MCP-S1"."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main/kotlin/Handler.kt",
        )

        mcp_s1_findings = [f for f in findings if f.id == "MCP-S1"]
        assert len(mcp_s1_findings) >= 1, (
            f"Expected at least one MCP-S1 finding for ScriptEngine.eval() code, "
            f"got {len(mcp_s1_findings)}. Code:\n{code}"
        )


class TestJavaDeserializationDetection:
    """Property 4 (Java subset): Unsafe Deserialization Detection.

    Feature: extended-mcp-scanning, Property 4: Unsafe Deserialization Detection Across Languages (Java subset)

    **Validates: Requirements 3.3**
    """

    analyzer = JavaAnalyzer()

    @given(code=java_object_input_stream_code())
    @settings(max_examples=100)
    def test_object_input_stream_detected_as_mcp_s8(self, code: str) -> None:
        """For any Java/Kotlin source file containing ObjectInputStream.readObject(),
        the JavaAnalyzer SHALL produce at least one ScanFinding with id="MCP-S8"."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main/java/Deserializer.java",
        )

        mcp_s8_findings = [f for f in findings if f.id == "MCP-S8"]
        assert len(mcp_s8_findings) >= 1, (
            f"Expected at least one MCP-S8 finding for ObjectInputStream code, "
            f"got {len(mcp_s8_findings)}. Code:\n{code}"
        )

    @given(code=java_xml_decoder_code())
    @settings(max_examples=100)
    def test_xml_decoder_detected_as_mcp_s8(self, code: str) -> None:
        """For any Java/Kotlin source file containing XMLDecoder,
        the JavaAnalyzer SHALL produce at least one ScanFinding with id="MCP-S8"."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main/java/Parser.java",
        )

        mcp_s8_findings = [f for f in findings if f.id == "MCP-S8"]
        assert len(mcp_s8_findings) >= 1, (
            f"Expected at least one MCP-S8 finding for XMLDecoder code, "
            f"got {len(mcp_s8_findings)}. Code:\n{code}"
        )

    @given(code=java_xstream_code())
    @settings(max_examples=100)
    def test_xstream_from_xml_detected_as_mcp_s8(self, code: str) -> None:
        """For any Java/Kotlin source file containing XStream.fromXML(),
        the JavaAnalyzer SHALL produce at least one ScanFinding with id="MCP-S8"."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main/java/XmlHandler.java",
        )

        mcp_s8_findings = [f for f in findings if f.id == "MCP-S8"]
        assert len(mcp_s8_findings) >= 1, (
            f"Expected at least one MCP-S8 finding for XStream.fromXML() code, "
            f"got {len(mcp_s8_findings)}. Code:\n{code}"
        )

    @given(code=java_kryo_code())
    @settings(max_examples=100)
    def test_kryo_read_object_detected_as_mcp_s8(self, code: str) -> None:
        """For any Java/Kotlin source file containing Kryo.readObject(),
        the JavaAnalyzer SHALL produce at least one ScanFinding with id="MCP-S8"."""
        findings = self.analyzer.scan(
            content=code,
            artifact_type=ArtifactType.MCP,
            artifact_path="server/src/main/java/Serializer.java",
        )

        mcp_s8_findings = [f for f in findings if f.id == "MCP-S8"]
        assert len(mcp_s8_findings) >= 1, (
            f"Expected at least one MCP-S8 finding for Kryo.readObject() code, "
            f"got {len(mcp_s8_findings)}. Code:\n{code}"
        )
