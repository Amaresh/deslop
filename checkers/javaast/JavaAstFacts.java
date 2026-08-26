import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.InitializerDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MarkerAnnotationExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.TextBlockLiteralExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.nodeTypes.NodeWithAnnotations;
import com.github.javaparser.ast.type.ClassOrInterfaceType;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parse a Java compilation unit and emit compact JSON facts for Python detectors.
 *
 * Usage:
 *   java -cp javaparser-core.jar:. JavaAstFacts file.java
 *   java -cp javaparser-core.jar:. JavaAstFacts --worker   # one path per stdin line
 */
public final class JavaAstFacts {
    private static final int MAX_SUMMARY = 400;
    private static final Set<String> HTTP_CLIENT_TYPES =
            Set.of("RestTemplate", "RestClient", "WebClient");
    private static final Set<String> QUERY_ANN =
            Set.of("Query", "NativeQuery", "NamedQuery");
    private static final Set<String> CREATE_QUERY =
            Set.of("createQuery", "createNativeQuery");

    private static final ParserConfiguration CONFIG = new ParserConfiguration()
            .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)
            .setAttributeComments(false);

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && "--worker".equals(args[0])) {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(System.in, StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) {
                if ("QUIT".equals(line)) {
                    break;
                }
                String json = factsOrNull(line);
                System.out.println(json == null ? "null" : json);
                System.out.flush();
            }
            return;
        }
        if (args.length != 1) {
            System.err.println("usage: JavaAstFacts <file.java> | --worker");
            System.exit(2);
        }
        String json = factsOrNull(args[0]);
        if (json == null) {
            System.err.println("parse error: " + args[0]);
            System.exit(1);
        }
        System.out.println(json);
    }

    static String factsOrNull(String filePath) {
        try {
            JavaParser parser = new JavaParser(CONFIG);
            ParseResult<CompilationUnit> result = parser.parse(Path.of(filePath));
            if (result.getResult().isEmpty()) {
                return null;
            }
            if (!result.isSuccessful()) {
                return null;
            }
            return emit(filePath, result.getResult().get());
        } catch (Exception e) {
            return null;
        }
    }

    static String emit(String file, CompilationUnit cu) {
        List<String> classes = new ArrayList<>();
        List<String> methods = new ArrayList<>();
        List<String> fields = new ArrayList<>();
        List<String> annotations = new ArrayList<>();
        List<String> concats = new ArrayList<>();

        for (AnnotationExpr ann : cu.findAll(AnnotationExpr.class)) {
            annotations.add(renderAnnotationFact(ann));
        }

        List<BinaryExpr> outermostConcats = new ArrayList<>();
        for (BinaryExpr bin : cu.findAll(BinaryExpr.class)) {
            if (bin.getOperator() != BinaryExpr.Operator.PLUS) {
                continue;
            }
            if (!isRecordableConcat(bin)) {
                continue;
            }
            if (isInnerPlus(bin)) {
                continue;
            }
            outermostConcats.add(bin);
            concats.add(renderConcat(bin, false));
        }

        for (TypeDeclaration<?> type : cu.findAll(TypeDeclaration.class)) {
            String owner = type.getFullyQualifiedName().orElse(type.getNameAsString());
            classes.add(obj(
                    "name", str(type.getNameAsString()),
                    "line", Integer.toString(lineOf(type)),
                    "annotations", arr(renderAnns(type)),
                    "supers", arr(renderSupers(type))
            ));
            for (FieldDeclaration fd : type.getFields()) {
                for (VariableDeclarator var : fd.getVariables()) {
                    fields.add(obj(
                            "name", str(var.getNameAsString()),
                            "type", str(var.getTypeAsString()),
                            "line", Integer.toString(lineOf(var)),
                            "owner", str(owner),
                            "annotations", arr(renderAnns(fd))
                    ));
                }
            }
            BodyBag instanceInit = new BodyBag();
            BodyBag staticInit = new BodyBag();
            for (FieldDeclaration fd : type.getFields()) {
                boolean isStatic = fd.isStatic();
                BodyBag bag = isStatic ? staticInit : instanceInit;
                for (VariableDeclarator var : fd.getVariables()) {
                    var.getInitializer().ifPresent(init -> {
                        bag.assigns.add(assignJson(var.getNameAsString(), init, lineOf(var)));
                        collectExpr(init, bag);
                    });
                }
            }
            for (BodyDeclaration<?> member : type.getMembers()) {
                if (member instanceof InitializerDeclaration) {
                    InitializerDeclaration init = (InitializerDeclaration) member;
                    BodyBag bag = init.isStatic() ? staticInit : instanceInit;
                    collectNode(init.getBody(), bag);
                }
            }
            if (!instanceInit.isEmpty()) {
                methods.add(methodJson("<instance-init>", lineOf(type), lineEnd(type),
                        List.of(), instanceInit, owner, List.of(), false, ""));
            }
            if (!staticInit.isEmpty()) {
                methods.add(methodJson("<clinit>", lineOf(type), lineEnd(type),
                        List.of(), staticInit, owner, List.of(), false, ""));
            }
            for (ConstructorDeclaration ctor : type.getConstructors()) {
                methods.add(callableJson(ctor, owner));
            }
            for (MethodDeclaration md : type.getMethods()) {
                methods.add(callableJson(md, owner));
            }
        }

        markCreateQueryConcats(cu, outermostConcats, concats);

        return obj(
                "file", str(file),
                "classes", arr(classes),
                "methods", arr(methods),
                "fields", arr(fields),
                "annotations", arr(annotations),
                "string_concats", arr(concats)
        );
    }

    private static void markCreateQueryConcats(
            CompilationUnit cu, List<BinaryExpr> concats, List<String> concatJson) {
        Set<Integer> queryConcatLines = new LinkedHashSet<>();
        for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
            if (!CREATE_QUERY.contains(call.getNameAsString()) || call.getArguments().isEmpty()) {
                continue;
            }
            Expression arg = peel(call.getArgument(0));
            if (arg instanceof NameExpr) {
                String var = ((NameExpr) arg).getNameAsString();
                Node scope = enclosingCallable(call);
                if (scope == null) {
                    continue;
                }
                for (AssignExpr as : scope.findAll(AssignExpr.class)) {
                    if (simpleLhs(as.getTarget()).equals(var) && containsPlus(as.getValue())) {
                        queryConcatLines.add(lineOf(as));
                    }
                }
                for (VariableDeclarator varDecl : scope.findAll(VariableDeclarator.class)) {
                    if (varDecl.getNameAsString().equals(var) && varDecl.getInitializer().isPresent()
                            && containsPlus(varDecl.getInitializer().get())) {
                        queryConcatLines.add(lineOf(varDecl));
                    }
                }
            }
        }
        if (queryConcatLines.isEmpty()) {
            return;
        }
        for (int i = 0; i < concats.size(); i++) {
            BinaryExpr bin = concats.get(i);
            if (queryConcatLines.contains(lineOf(bin))) {
                concatJson.set(i, renderConcat(bin, true));
            }
        }
    }

    private static String callableJson(CallableDeclaration<?> callable, String owner) {
        BodyBag bag = new BodyBag();
        if (callable instanceof MethodDeclaration) {
            ((MethodDeclaration) callable).getBody().ifPresent(b -> collectNode(b, bag));
        } else if (callable instanceof ConstructorDeclaration) {
            collectNode(((ConstructorDeclaration) callable).getBody(), bag);
        }
        String returns = "";
        if (callable instanceof MethodDeclaration) {
            returns = ((MethodDeclaration) callable).getTypeAsString();
        }
        return methodJson(
                callable.getNameAsString(),
                lineOf(callable),
                lineEnd(callable),
                renderAnns(callable),
                bag,
                owner,
                renderParams(callable),
                callable.isPublic(),
                returns);
    }

    private static List<String> renderParams(CallableDeclaration<?> callable) {
        List<String> out = new ArrayList<>();
        for (Parameter p : callable.getParameters()) {
            out.add(obj(
                    "name", str(p.getNameAsString()),
                    "type", str(p.getTypeAsString())
            ));
        }
        return out;
    }

    private static String methodJson(
            String name, int start, int end, List<String> anns, BodyBag bag,
            String owner, List<String> params, boolean isPublic, String returns) {
        return obj(
                "name", str(name),
                "line_start", Integer.toString(start),
                "line_end", Integer.toString(end),
                "annotations", arr(anns),
                "owner", str(owner),
                "calls", arr(bag.calls),
                "news", arr(bag.news),
                "assigns", arr(bag.assigns),
                "params", arr(params),
                "public", isPublic ? "true" : "false",
                "returns", str(returns)
        );
    }

    private static List<String> renderSupers(TypeDeclaration<?> type) {
        List<String> out = new ArrayList<>();
        if (!(type instanceof ClassOrInterfaceDeclaration)) {
            return out;
        }
        ClassOrInterfaceDeclaration cid = (ClassOrInterfaceDeclaration) type;
        for (ClassOrInterfaceType t : cid.getExtendedTypes()) {
            out.add(strValue(compact(t.toString())));
        }
        for (ClassOrInterfaceType t : cid.getImplementedTypes()) {
            out.add(strValue(compact(t.toString())));
        }
        return out;
    }

    private static void collectNode(Node node, BodyBag bag) {
        for (MethodCallExpr call : node.findAll(MethodCallExpr.class)) {
            bag.calls.add(obj(
                    "name", str(calleeName(call)),
                    "line", Integer.toString(lineOf(call)),
                    "args_summary", arr(argSummaries(call))
            ));
            maybeBuilderNews(call, bag);
        }
        for (ObjectCreationExpr oce : node.findAll(ObjectCreationExpr.class)) {
            List<String> chained = chainAfter(oce);
            bag.news.add(obj(
                    "type", str(simpleType(oce.getTypeAsString())),
                    "line", Integer.toString(lineOf(oce)),
                    "arg_count", Integer.toString(oce.getArguments().size()),
                    "chained", strArr(chained)
            ));
        }
        for (AssignExpr as : node.findAll(AssignExpr.class)) {
            bag.assigns.add(assignJson(simpleLhs(as.getTarget()), as.getValue(), lineOf(as)));
        }
        for (VariableDeclarator var : node.findAll(VariableDeclarator.class)) {
            if (var.getInitializer().isPresent() && var.getParentNode().isPresent()
                    && var.getParentNode().get() instanceof VariableDeclarationExpr) {
                bag.assigns.add(assignJson(
                        var.getNameAsString(), var.getInitializer().get(), lineOf(var)));
            }
        }
    }

    private static void collectExpr(Expression expr, BodyBag bag) {
        collectNode(expr, bag);
    }

    private static void maybeBuilderNews(MethodCallExpr call, BodyBag bag) {
        String meth = call.getNameAsString();
        if (!"build".equals(meth) && !"create".equals(meth)) {
            return;
        }
        Chain chain = walkChain(call);
        if (chain.rootType == null || !HTTP_CLIENT_TYPES.contains(chain.rootType)) {
            return;
        }
        if (chain.fromNew) {
            return;
        }
        bag.news.add(obj(
                "type", str(chain.rootType),
                "line", Integer.toString(lineOf(call)),
                "arg_count", Integer.toString(call.getArguments().size()),
                "chained", strArr(chain.methods)
        ));
    }

    private static List<String> chainAfter(ObjectCreationExpr oce) {
        List<String> chained = new ArrayList<>();
        Node cur = oce;
        while (cur.getParentNode().isPresent()
                && cur.getParentNode().get() instanceof MethodCallExpr) {
            MethodCallExpr parent = (MethodCallExpr) cur.getParentNode().get();
            if (!parent.getScope().isPresent() || parent.getScope().get() != cur) {
                break;
            }
            chained.add(parent.getNameAsString());
            cur = parent;
        }
        return chained;
    }

    private static Chain walkChain(MethodCallExpr call) {
        List<String> methods = new ArrayList<>();
        Expression cur = call;
        while (cur instanceof MethodCallExpr) {
            MethodCallExpr mc = (MethodCallExpr) cur;
            methods.add(0, mc.getNameAsString());
            if (mc.getScope().isEmpty()) {
                return new Chain(null, methods, false);
            }
            cur = peel(mc.getScope().get());
        }
        if (cur instanceof NameExpr) {
            return new Chain(((NameExpr) cur).getNameAsString(), methods, false);
        }
        if (cur instanceof ObjectCreationExpr) {
            return new Chain(
                    simpleType(((ObjectCreationExpr) cur).getTypeAsString()),
                    methods,
                    true);
        }
        if (cur instanceof com.github.javaparser.ast.expr.FieldAccessExpr) {
            return new Chain(
                    ((com.github.javaparser.ast.expr.FieldAccessExpr) cur).getNameAsString(),
                    methods,
                    false);
        }
        return new Chain(null, methods, false);
    }

    private static String calleeName(MethodCallExpr call) {
        if (call.getScope().isPresent()) {
            return trunc(compact(call.getScope().get().toString()) + "." + call.getNameAsString());
        }
        return call.getNameAsString();
    }

    private static List<String> argSummaries(MethodCallExpr call) {
        List<String> out = new ArrayList<>();
        for (Expression arg : call.getArguments()) {
            out.add(strValue(trunc(compact(arg.toString()))));
        }
        return out;
    }

    private static List<String> renderAnns(NodeWithAnnotations<?> node) {
        List<String> out = new ArrayList<>();
        for (AnnotationExpr ann : node.getAnnotations()) {
            out.add(strValue(compact(ann.toString())));
        }
        return out;
    }

    private static String renderAnnotationFact(AnnotationExpr ann) {
        Map<String, String> members = new LinkedHashMap<>();
        if (ann instanceof SingleMemberAnnotationExpr) {
            members.put("value", compact(((SingleMemberAnnotationExpr) ann).getMemberValue().toString()));
        } else if (ann instanceof NormalAnnotationExpr) {
            for (MemberValuePair pair : ((NormalAnnotationExpr) ann).getPairs()) {
                members.put(pair.getNameAsString(), compact(pair.getValue().toString()));
            }
        } else if (ann instanceof MarkerAnnotationExpr) {
            // no members
        }
        StringBuilder mem = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : members.entrySet()) {
            if (!first) {
                mem.append(',');
            }
            first = false;
            mem.append(strValue(e.getKey())).append(':').append(strValue(e.getValue()));
        }
        mem.append('}');
        return obj(
                "name", str(ann.getName().getIdentifier()),
                "line", Integer.toString(lineOf(ann)),
                "members", mem.toString()
        );
    }

    private static String renderConcat(BinaryExpr bin, boolean forceCreateQuery) {
        boolean inAnn = ancestorQueryAnn(bin);
        boolean inCreate = forceCreateQuery || ancestorCreateQuery(bin);
        return obj(
                "line", Integer.toString(lineOf(bin)),
                "summary", str(trunc(compact(bin.toString()))),
                "in_query_ann", inAnn ? "true" : "false",
                "in_create_query", inCreate ? "true" : "false"
        );
    }

    private static boolean isRecordableConcat(BinaryExpr bin) {
        return looksStringy(bin.getLeft()) || looksStringy(bin.getRight())
                || ancestorQueryAnn(bin) || ancestorCreateQuery(bin);
    }

    private static boolean looksStringy(Expression expr) {
        Expression e = peel(expr);
        if (e instanceof StringLiteralExpr || e instanceof TextBlockLiteralExpr) {
            return true;
        }
        if (e instanceof BinaryExpr) {
            BinaryExpr b = (BinaryExpr) e;
            return b.getOperator() == BinaryExpr.Operator.PLUS
                    && (looksStringy(b.getLeft()) || looksStringy(b.getRight()));
        }
        return false;
    }

    private static boolean isInnerPlus(BinaryExpr bin) {
        Node n = bin.getParentNode().orElse(null);
        while (n instanceof EnclosedExpr) {
            n = n.getParentNode().orElse(null);
        }
        return n instanceof BinaryExpr
                && ((BinaryExpr) n).getOperator() == BinaryExpr.Operator.PLUS;
    }

    private static boolean ancestorQueryAnn(Node node) {
        Node n = node;
        while (n != null) {
            if (n instanceof AnnotationExpr) {
                return QUERY_ANN.contains(((AnnotationExpr) n).getName().getIdentifier());
            }
            n = n.getParentNode().orElse(null);
        }
        return false;
    }

    private static boolean ancestorCreateQuery(Node node) {
        Node n = node;
        while (n != null) {
            if (n instanceof MethodCallExpr) {
                if (CREATE_QUERY.contains(((MethodCallExpr) n).getNameAsString())) {
                    return true;
                }
            }
            n = n.getParentNode().orElse(null);
        }
        return false;
    }

    private static Node enclosingCallable(Node node) {
        Node n = node;
        while (n != null) {
            if (n instanceof MethodDeclaration || n instanceof ConstructorDeclaration) {
                return n;
            }
            n = n.getParentNode().orElse(null);
        }
        return null;
    }

    private static boolean containsPlus(Expression expr) {
        return expr.findFirst(BinaryExpr.class,
                b -> b.getOperator() == BinaryExpr.Operator.PLUS).isPresent();
    }

    private static Expression peel(Expression expr) {
        Expression e = expr;
        while (e instanceof EnclosedExpr) {
            e = ((EnclosedExpr) e).getInner();
        }
        return e;
    }

    private static String simpleLhs(Expression target) {
        String s = compact(target.toString());
        int dot = s.lastIndexOf('.');
        return dot >= 0 ? s.substring(dot + 1) : s;
    }

    private static String simpleType(String raw) {
        String s = raw.replace("[]", "");
        int lt = s.indexOf('<');
        if (lt >= 0) {
            s = s.substring(0, lt);
        }
        int dot = s.lastIndexOf('.');
        return dot >= 0 ? s.substring(dot + 1).trim() : s.trim();
    }

    private static String assignJson(String lhs, Expression rhs, int line) {
        return obj(
                "lhs", str(lhs),
                "rhs_summary", str(trunc(compact(rhs.toString()))),
                "line", Integer.toString(line)
        );
    }

    private static int lineOf(Node node) {
        return node.getBegin().map(p -> p.line).orElse(0);
    }

    private static int lineEnd(Node node) {
        return node.getEnd().map(p -> p.line).orElse(lineOf(node));
    }

    private static String compact(String s) {
        return s.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
    }

    private static String trunc(String s) {
        if (s.length() <= MAX_SUMMARY) {
            return s;
        }
        return s.substring(0, MAX_SUMMARY - 3) + "...";
    }

    private static String str(String s) {
        return strValue(s);
    }

    private static String strValue(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private static String obj(String... kv) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(strValue(kv[i])).append(':').append(kv[i + 1]);
        }
        sb.append('}');
        return sb.toString();
    }

    private static String arr(List<String> items) {
        StringBuilder sb = new StringBuilder();
        sb.append('[');
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(items.get(i));
        }
        sb.append(']');
        return sb.toString();
    }

    private static String strArr(List<String> items) {
        List<String> quoted = new ArrayList<>(items.size());
        for (String item : items) {
            quoted.add(strValue(item));
        }
        return arr(quoted);
    }

    private static final class BodyBag {
        final List<String> calls = new ArrayList<>();
        final List<String> news = new ArrayList<>();
        final List<String> assigns = new ArrayList<>();

        boolean isEmpty() {
            return calls.isEmpty() && news.isEmpty() && assigns.isEmpty();
        }
    }

    private static final class Chain {
        final String rootType;
        final List<String> methods;
        final boolean fromNew;

        Chain(String rootType, List<String> methods, boolean fromNew) {
            this.rootType = rootType;
            this.methods = methods;
            this.fromNew = fromNew;
        }
    }
}
