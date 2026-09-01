# javaast — AST facts extractor for Java stopthatslop detectors

JavaParser-based helper that parses a `.java` file and emits structural JSON
facts. Python detectors consume these facts instead of regexing source text.

## Build

OpenJDK 21 (`javac`, `java`) plus JavaParser core 3.26.x (gitignored jar):

```sh
cd checkers/javaast
curl -fsSL -o javaparser-core-3.26.4.jar \
  https://repo1.maven.org/maven2/com/github/javaparser/javaparser-core/3.26.4/javaparser-core-3.26.4.jar
javac -cp javaparser-core-3.26.4.jar JavaAstFacts.java
```

`javaast_client.py` downloads the jar if missing, then refuses it unless
SHA-256 is `3b2d6c4451b2c675d4f4be10784c5681049529d11f3c4e5936f08ba90dd45c27`.

## Usage

```sh
java -cp javaparser-core-3.26.4.jar:. JavaAstFacts path/to/File.java
java -cp javaparser-core-3.26.4.jar:. JavaAstFacts --worker   # one path per stdin line
```

Parse errors go to stderr (one-shot exit 1) or emit JSON `null` (worker).
The worker stays alive so `stopthatslop check` does not pay JVM
startup per file.

Language level is Java 21 (`ParserConfiguration.setLanguageLevel`).

## Output schema

Top level: `file`, `classes`, `methods`, `annotations`, `string_concats`,
`string_constants`. Extra (detectors may use): `fields`, per-method `owner` /
`assigns`. `@Query` members may include `value_resolved` when the expression
is a string literal, text block, or concat of those.

`news.chained` is the builder method names after `new X()` or `X.builder()` /
`X.create()`. `string_concats` sets `in_query_ann` / `in_create_query` from
AST ancestors, plus one-hop assignment into `createQuery`/`createNativeQuery`.
