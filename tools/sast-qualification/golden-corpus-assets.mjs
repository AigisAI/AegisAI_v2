import { createHash } from 'node:crypto';
import { lstat, mkdir, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  SAST_QUALIFICATION_NEGATIVE_KINDS,
  buildSastQualificationCorpusCase,
  buildSastQualificationCorpusSnapshot
} from '../../packages/shared/dist/index.js';

export const GOLDEN_CORPUS_REVISION = '1.0.0';
export const GOLDEN_CORPUS_PUBLISHED_AT = '2026-08-20T00:00:00.000Z';
export const GOLDEN_CORPUS_OWNER =
  'team://security-engineering/sast-qualification';
export const GOLDEN_CORPUS_LICENSE = 'Apache-2.0';

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
export const GOLDEN_CORPUS_ROOT = resolve(
  moduleDirectory,
  '../../qualification/corpora/v1'
);
export const GOLDEN_CORPUS_SNAPSHOT_PATH = join(
  GOLDEN_CORPUS_ROOT,
  'golden-corpus.snapshot.json'
);

const GOLDEN_CORPUS_PROVENANCE = digestBoundReference(
  'sast-corpus-provenance://aegisai/t051/golden-v1',
  'aegisai-t051-golden-corpus-provenance-v1'
);
const PRIOR_RELEASE_REFERENCE = digestBoundReference(
  'sast-release://aegisai/sast/2026.08.0',
  'aegisai-sast-release-2026.08.0'
);

const JAVA_CONTEXTS = [
  'queryParameter',
  'headerValue',
  'cookieValue',
  'pathVariable',
  'formField',
  'jsonProperty',
  'xmlValue',
  'messageBody',
  'queueAttribute',
  'rpcArgument',
  'webhookField',
  'csvColumn',
  'yamlProperty',
  'configValue',
  'environmentValue',
  'cliArgument',
  'metadataValue',
  'recordField',
  'importedValue',
  'requestAttribute'
];

const JAVA_FAMILIES = [
  javaFamily('sql-injection', 'aegis.java.cwe-89.sql-injection', 'HIGH'),
  javaFamily('command-injection', 'aegis.java.cwe-78.command-injection', 'CRITICAL'),
  javaFamily('path-traversal', 'aegis.java.cwe-22.path-traversal', 'HIGH'),
  javaFamily('ssrf', 'aegis.java.cwe-918.ssrf', 'HIGH'),
  javaFamily('ldap-injection', 'aegis.java.cwe-90.ldap-injection', 'HIGH'),
  javaFamily('xpath-injection', 'aegis.java.cwe-643.xpath-injection', 'HIGH'),
  javaFamily(
    'unsafe-deserialization',
    'aegis.java.cwe-502.unsafe-deserialization',
    'CRITICAL'
  ),
  javaFamily('xxe', 'aegis.java.cwe-611.xxe', 'HIGH'),
  javaFamily('weak-crypto', 'aegis.java.cwe-327.weak-crypto', 'HIGH'),
  javaFamily('log-injection', 'aegis.java.cwe-117.log-injection', 'HIGH')
];

const COMMON_FAMILIES = [
  commonFamily(
    'log4shell-maven',
    'aegis.trivy.dependency.cve-2021-44228',
    'CRITICAL',
    'DEPENDENCY_VULNERABILITY',
    'pom.xml'
  ),
  commonFamily(
    'jackson-maven',
    'aegis.trivy.dependency.jackson-databind-legacy',
    'HIGH',
    'DEPENDENCY_VULNERABILITY',
    'pom.xml'
  ),
  commonFamily(
    'spring-gradle',
    'aegis.trivy.dependency.cve-2022-22965',
    'CRITICAL',
    'DEPENDENCY_VULNERABILITY',
    'build.gradle'
  ),
  commonFamily(
    'lodash-npm',
    'aegis.trivy.dependency.cve-2021-23337',
    'HIGH',
    'DEPENDENCY_VULNERABILITY',
    'package.json'
  ),
  commonFamily(
    'aws-access-key',
    'aegis.trivy.secret.aws-access-key',
    'CRITICAL',
    'SECRET_DETECTION',
    '.env'
  ),
  commonFamily(
    'github-token',
    'aegis.trivy.secret.github-pat',
    'CRITICAL',
    'SECRET_DETECTION',
    '.env'
  ),
  commonFamily(
    'private-key',
    'aegis.trivy.secret.private-key',
    'CRITICAL',
    'SECRET_DETECTION',
    'secrets.env'
  ),
  commonFamily(
    'docker-root-user',
    'aegis.trivy.iac.docker-root-user',
    'HIGH',
    'IAC_MISCONFIGURATION',
    'Dockerfile'
  ),
  commonFamily(
    'terraform-public-storage',
    'aegis.trivy.iac.terraform-public-storage',
    'CRITICAL',
    'IAC_MISCONFIGURATION',
    'main.tf'
  ),
  commonFamily(
    'kubernetes-privileged',
    'aegis.trivy.iac.kubernetes-privileged',
    'CRITICAL',
    'IAC_MISCONFIGURATION',
    'deployment.yaml'
  )
];

export function createGoldenCorpusAssets() {
  const sources = new Map();
  const cases = [];
  for (const family of [...JAVA_FAMILIES, ...COMMON_FAMILIES]) {
    for (const corpusClass of ['GOLDEN_POSITIVE', 'GOLDEN_NEGATIVE']) {
      const rendered = renderBundle(family, corpusClass);
      sources.set(rendered.sourcePath, rendered.text);
      const sourceDigest = digest(rendered.text);
      const sourceBytes = Buffer.byteLength(rendered.text, 'utf8');
      for (const block of rendered.blocks) {
        const caseInput = {
          caseKey: block.caseKey,
          pairKey: block.pairKey,
          caseRevision: GOLDEN_CORPUS_REVISION,
          corpusClass,
          negativeKind: block.negativeKind,
          ownerRef: GOLDEN_CORPUS_OWNER,
          licenseExpression: GOLDEN_CORPUS_LICENSE,
          provenanceRef: GOLDEN_CORPUS_PROVENANCE,
          profiles: profilesFor(family.capability),
          language: family.language,
          scanner: family.scanner,
          capability: family.capability,
          ruleSemanticId: family.ruleSemanticId,
          ruleRevision: '1.0.0',
          severity: family.severity,
          expectedOutcome:
            corpusClass === 'GOLDEN_POSITIVE' ? 'DETECT' : 'NO_FINDING',
          expectedFindingCount: corpusClass === 'GOLDEN_POSITIVE' ? 1 : 0,
          sourcePath: rendered.sourcePath,
          scanPath: block.scanPath,
          sourceDigest,
          sourceBytes,
          expectedAnchor: block.anchor,
          startLine: block.startLine,
          endLine: block.endLine
        };
        const value = buildSastQualificationCorpusCase(caseInput, digest);
        if (!value) {
          throw new Error(`invalid generated case: ${block.caseKey}`);
        }
        cases.push(value);
      }
    }
  }
  const snapshot = buildSastQualificationCorpusSnapshot(
    {
      revision: GOLDEN_CORPUS_REVISION,
      publishedAt: GOLDEN_CORPUS_PUBLISHED_AT,
      ownerRef: GOLDEN_CORPUS_OWNER,
      licenseExpression: GOLDEN_CORPUS_LICENSE,
      provenanceRef: GOLDEN_CORPUS_PROVENANCE,
      priorReleaseRef: PRIOR_RELEASE_REFERENCE,
      cases
    },
    digest
  );
  if (!snapshot) throw new Error('invalid generated golden corpus snapshot');
  return { snapshot, sources };
}

export async function writeGoldenCorpusAssets() {
  const assets = createGoldenCorpusAssets();
  await assertSafeCorpusWriteTargets();
  const expectedPaths = new Set(assets.sources.keys());
  const existingPaths = await listSourceFiles(join(GOLDEN_CORPUS_ROOT, 'sources'));
  const stale = existingPaths.filter((path) => !expectedPaths.has(path));
  if (stale.length > 0) {
    throw new Error(`refusing to leave stale corpus sources: ${stale.join(', ')}`);
  }
  for (const [sourcePath, text] of assets.sources) {
    const output = safeCorpusPath(sourcePath);
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, text, { encoding: 'utf8' });
  }
  await writeFile(
    GOLDEN_CORPUS_SNAPSHOT_PATH,
    `${JSON.stringify(assets.snapshot, null, 2)}\n`,
    { encoding: 'utf8' }
  );
  return assets;
}

function renderBundle(family, corpusClass) {
  const polarity = corpusClass === 'GOLDEN_POSITIVE' ? 'positive' : 'negative';
  const sourcePath = `sources/${family.language.toLowerCase()}/${family.slug}.${polarity}.bundle`;
  const lines = [];
  const blocks = [];
  for (let index = 0; index < 20; index += 1) {
    const ordinal = String(index + 1).padStart(3, '0');
    const negativeKind =
      corpusClass === 'GOLDEN_NEGATIVE'
        ? SAST_QUALIFICATION_NEGATIVE_KINDS[
            index % SAST_QUALIFICATION_NEGATIVE_KINDS.length
          ]
        : null;
    const anchor = `t051.${family.slug}.${polarity}.${ordinal}`;
    const pairKey = `${family.language.toLowerCase()}.${family.slug}.${ordinal}`;
    const caseKey = `${pairKey}.${polarity}`;
    const scanPath = scanPathFor(family, polarity, ordinal, negativeKind);
    const snippet =
      family.language === 'JAVA'
        ? javaSnippet(family.slug, polarity, ordinal, anchor, negativeKind)
        : commonSnippet(family.slug, polarity, ordinal, anchor, negativeKind);
    lines.push(`<<<T051:${anchor}>>>`);
    const startLine = lines.length + 1;
    const snippetLines = snippet.split('\n');
    lines.push(...snippetLines);
    const endLine = lines.length;
    lines.push(`<<<END:${anchor}>>>`, '');
    blocks.push({
      anchor,
      caseKey,
      pairKey,
      negativeKind,
      scanPath,
      startLine,
      endLine
    });
  }
  return { sourcePath, text: lines.join('\n'), blocks };
}

function javaSnippet(slug, polarity, ordinal, anchor, negativeKind) {
  const input = `${JAVA_CONTEXTS[Number(ordinal) - 1]}${ordinal}`;
  const className = `${pascal(slug)}${polarity === 'positive' ? 'Positive' : 'Negative'}${ordinal}`;
  const unsafeAsData =
    negativeKind === 'COMMENT_OR_STRING' ||
    negativeKind === 'GENERATED_OR_VENDOR';
  const body = javaBody(slug, polarity, input, ordinal, negativeKind, unsafeAsData);
  return [
    `// ${anchor}`,
    'package qualification.corpus;',
    `final class ${className} {`,
    `  void evaluate(String ${input}) throws Exception {`,
    ...body.map((line) => `    ${line}`),
    '  }',
    '}'
  ].join('\n');
}

function javaBody(slug, polarity, input, ordinal, negativeKind, unsafeAsData) {
  if (unsafeAsData) {
    return [
      `String documentation${ordinal} = "unsafe example for ${slug}: " + ${input}.length();`,
      `System.out.print(documentation${ordinal}.length());`
    ];
  }
  const positive = polarity === 'positive';
  switch (slug) {
    case 'sql-injection':
      return positive
        ? [
            `java.sql.Statement statement${ordinal} = null;`,
            `statement${ordinal}.executeQuery("SELECT * FROM account WHERE id='" + ${input} + "'");`
          ]
        : [
            `java.sql.PreparedStatement statement${ordinal} = null;`,
            `statement${ordinal}.setString(1, ${safeValue(input, negativeKind)});`
          ];
    case 'command-injection':
      return positive
        ? [`Runtime.getRuntime().exec("/usr/bin/tool " + ${input});`]
        : [
            `java.util.List<String> allowed${ordinal} = java.util.List.of("status", "version");`,
            `new ProcessBuilder("/usr/bin/tool", allowed${ordinal}.contains(${input}) ? ${input} : "status");`
          ];
    case 'path-traversal':
      return positive
        ? [`java.nio.file.Path path${ordinal} = java.nio.file.Paths.get("/srv/data", ${input});`]
        : [
            `java.nio.file.Path root${ordinal} = java.nio.file.Paths.get("/srv/data").normalize();`,
            `java.nio.file.Path path${ordinal} = root${ordinal}.resolve(${safeValue(input, negativeKind)}).normalize();`,
            `if (!path${ordinal}.startsWith(root${ordinal})) throw new SecurityException();`
          ];
    case 'ssrf':
      return positive
        ? [`new java.net.URL(${input}).openConnection();`]
        : [
            `java.net.URI uri${ordinal} = java.net.URI.create(${safeValue(input, negativeKind)});`,
            `if (!"https".equals(uri${ordinal}.getScheme()) || !"api.example.test".equals(uri${ordinal}.getHost())) throw new SecurityException();`
          ];
    case 'ldap-injection':
      return positive
        ? [
            `javax.naming.directory.DirContext context${ordinal} = null;`,
            `context${ordinal}.search("ou=users", "(uid=" + ${input} + ")", null);`
          ]
        : [
            `String escaped${ordinal} = ${safeValue(input, negativeKind)}.replace("*", "\\\\2a").replace("(", "\\\\28").replace(")", "\\\\29");`,
            `System.out.print(escaped${ordinal}.length());`
          ];
    case 'xpath-injection':
      return positive
        ? [
            `javax.xml.xpath.XPath xpath${ordinal} = javax.xml.xpath.XPathFactory.newInstance().newXPath();`,
            `xpath${ordinal}.evaluate("//user[name='" + ${input} + "']", (Object) null);`
          ]
        : [
            `javax.xml.xpath.XPath xpath${ordinal} = javax.xml.xpath.XPathFactory.newInstance().newXPath();`,
            `xpath${ordinal}.evaluate("//user[@active='true']", (Object) null);`
          ];
    case 'unsafe-deserialization':
      return positive
        ? [
            `java.io.ObjectInputStream stream${ordinal} = null;`,
            `stream${ordinal}.readObject();`
          ]
        : [
            `java.io.ObjectInputStream stream${ordinal} = null;`,
            `stream${ordinal}.setObjectInputFilter(java.io.ObjectInputFilter.Config.createFilter("java.base/*;!*"));`
          ];
    case 'xxe':
      return positive
        ? [
            `javax.xml.parsers.DocumentBuilderFactory factory${ordinal} = javax.xml.parsers.DocumentBuilderFactory.newInstance();`,
            `factory${ordinal}.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(${input}.getBytes(java.nio.charset.StandardCharsets.UTF_8)));`
          ]
        : [
            `javax.xml.parsers.DocumentBuilderFactory factory${ordinal} = javax.xml.parsers.DocumentBuilderFactory.newInstance();`,
            `factory${ordinal}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`,
            `factory${ordinal}.setExpandEntityReferences(false);`
          ];
    case 'weak-crypto':
      return [
        `java.security.MessageDigest digest${ordinal} = java.security.MessageDigest.getInstance("${positive ? 'MD5' : 'SHA-256'}");`,
        `digest${ordinal}.digest(${input}.getBytes(java.nio.charset.StandardCharsets.UTF_8));`
      ];
    case 'log-injection':
      return positive
        ? [`System.getLogger("audit").log(System.Logger.Level.INFO, "user=" + ${input});`]
        : [
            `String safe${ordinal} = ${safeValue(input, negativeKind)}.replace("\\r", "_").replace("\\n", "_");`,
            `System.getLogger("audit").log(System.Logger.Level.INFO, "user=" + safe${ordinal});`
          ];
    default:
      throw new Error(`unknown Java corpus family: ${slug}`);
  }
}

function commonSnippet(slug, polarity, ordinal, anchor, negativeKind) {
  const positive = polarity === 'positive';
  const inert =
    !positive &&
    (negativeKind === 'COMMENT_OR_STRING' ||
      negativeKind === 'GENERATED_OR_VENDOR');
  switch (slug) {
    case 'log4shell-maven':
      return mavenSnippet(
        anchor,
        'org.apache.logging.log4j',
        'log4j-core',
        positive && !inert ? '2.14.1' : '2.17.1',
        inert
      );
    case 'jackson-maven':
      return mavenSnippet(
        anchor,
        'com.fasterxml.jackson.core',
        'jackson-databind',
        positive && !inert ? '2.9.9' : '2.15.4',
        inert
      );
    case 'spring-gradle':
      return [
        `// ${anchor}`,
        inert ? '// implementation("org.springframework:spring-core:5.3.17")' : 'dependencies {',
        inert
          ? '// generated/vendor documentation only'
          : `  implementation("org.springframework:spring-core:${positive ? '5.3.17' : '5.3.20'}")`,
        inert ? '// no dependency declaration' : '}'
      ].join('\n');
    case 'lodash-npm':
      return JSON.stringify(
        {
          name: `t051-${anchor.replaceAll('.', '-')}`,
          version: '1.0.0',
          description: inert
            ? `${anchor}: lodash 4.17.20 appears only in documentation`
            : anchor,
          dependencies: inert ? {} : { lodash: positive ? '4.17.20' : '4.17.21' }
        },
        null,
        2
      );
    case 'aws-access-key':
      return envSecretSnippet(
        anchor,
        'AWS_ACCESS_KEY_ID',
        positive && !inert ? `AKIA${syntheticToken(ordinal, 16, 'A')}` : 'EXAMPLE_AWS_KEY',
        inert
      );
    case 'github-token':
      return envSecretSnippet(
        anchor,
        'GITHUB_TOKEN',
        positive && !inert ? `ghp_${syntheticToken(ordinal, 36, 'g')}` : 'EXAMPLE_GITHUB_TOKEN',
        inert
      );
    case 'private-key':
      return envSecretSnippet(
        anchor,
        'PRIVATE_KEY',
        positive && !inert
          ? `-----BEGIN PRIVATE KEY-----${syntheticToken(ordinal, 48, 'K')}-----END PRIVATE KEY-----`
          : 'EXAMPLE_PRIVATE_KEY_REFERENCE',
        inert
      );
    case 'docker-root-user':
      return [
        `# ${anchor}`,
        'FROM scratch',
        inert ? '# USER root appears only in documentation' : `USER ${positive ? 'root' : '65532'}`,
        'ENTRYPOINT ["/app"]'
      ].join('\n');
    case 'terraform-public-storage':
      return [
        `# ${anchor}`,
        `resource "aws_s3_bucket" "case_${ordinal}" {`,
        `  bucket = "t051-case-${ordinal}"`,
        inert ? '  # acl = "public-read" is documentation only' : `  acl = "${positive ? 'public-read' : 'private'}"`,
        '}'
      ].join('\n');
    case 'kubernetes-privileged':
      return [
        `# ${anchor}`,
        'apiVersion: apps/v1',
        'kind: Deployment',
        'metadata:',
        `  name: t051-case-${ordinal}`,
        'spec:',
        '  template:',
        '    spec:',
        '      containers:',
        '        - name: app',
        '          image: registry.example.test/aegis/t051@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        '          securityContext:',
        inert ? '            # privileged: true is documentation only' : `            privileged: ${positive ? 'true' : 'false'}`,
        ...(positive || inert
          ? []
          : ['            runAsNonRoot: true', '            allowPrivilegeEscalation: false'])
      ].join('\n');
    default:
      throw new Error(`unknown common corpus family: ${slug}`);
  }
}

function mavenSnippet(anchor, groupId, artifactId, version, inert) {
  return [
    `<!-- ${anchor} -->`,
    '<project xmlns="http://maven.apache.org/POM/4.0.0">',
    '  <modelVersion>4.0.0</modelVersion>',
    '  <groupId>test.aegis.qualification</groupId>',
    `  <artifactId>${anchor.replaceAll('.', '-')}</artifactId>`,
    '  <version>1.0.0</version>',
    ...(inert
      ? [`  <!-- ${groupId}:${artifactId}:2.14.1 is documentation only -->`]
      : [
          '  <dependencies>',
          '    <dependency>',
          `      <groupId>${groupId}</groupId>`,
          `      <artifactId>${artifactId}</artifactId>`,
          `      <version>${version}</version>`,
          '    </dependency>',
          '  </dependencies>'
        ]),
    '</project>'
  ].join('\n');
}

function envSecretSnippet(anchor, key, value, inert) {
  return [
    `# ${anchor}`,
    inert ? `# ${key}=${value}` : `${key}=${value}`,
    'QUALIFICATION_FIXTURE=true'
  ].join('\n');
}

function safeValue(input, negativeKind) {
  return negativeKind === 'SANITIZER'
    ? `${input}.replaceAll("[^A-Za-z0-9._-]", "")`
    : input;
}

function scanPathFor(family, polarity, ordinal, negativeKind) {
  const scope =
    negativeKind === 'GENERATED_OR_VENDOR'
      ? family.language === 'JAVA'
        ? `generated/${family.slug}`
        : `vendor/${family.slug}`
      : family.slug;
  const fileName =
    family.language === 'JAVA'
      ? `${pascal(family.slug)}${polarity === 'positive' ? 'Positive' : 'Negative'}${ordinal}.java`
      : family.fileName;
  return `workspace/${family.language.toLowerCase()}/${scope}/${polarity}/${ordinal}/${fileName}`;
}

function profilesFor(capability) {
  if (capability === 'SAST') return ['JAVA_FAST_V1', 'JAVA_DEEP_V1'];
  if (
    capability === 'DEPENDENCY_VULNERABILITY' ||
    capability === 'SECRET_DETECTION'
  ) {
    return ['JAVA_FAST_V1', 'JAVA_DEEP_V1', 'COMMON_DEEP_V1'];
  }
  return ['JAVA_DEEP_V1', 'COMMON_DEEP_V1'];
}

function javaFamily(slug, ruleSemanticId, severity) {
  return {
    slug,
    ruleSemanticId,
    severity,
    capability: 'SAST',
    scanner: 'OPENGREP',
    language: 'JAVA'
  };
}

function commonFamily(
  slug,
  ruleSemanticId,
  severity,
  capability,
  fileName
) {
  return {
    slug,
    ruleSemanticId,
    severity,
    capability,
    fileName,
    scanner: 'TRIVY',
    language: 'COMMON'
  };
}

function pascal(value) {
  return value
    .split('-')
    .map((part) => `${part[0].toUpperCase()}${part.slice(1)}`)
    .join('');
}

function syntheticToken(ordinal, length, seed) {
  const source = createHash('sha256')
    .update(`aegisai-t051-synthetic-${seed}-${ordinal}`)
    .digest('hex')
    .toUpperCase();
  return `${seed}${source}`.repeat(Math.ceil(length / (source.length + 1))).slice(0, length);
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function digestBoundReference(prefix, value) {
  return `${prefix}/${digest(value)}`;
}

function safeCorpusPath(sourcePath) {
  const output = resolve(GOLDEN_CORPUS_ROOT, ...sourcePath.split('/'));
  const relativePath = relative(GOLDEN_CORPUS_ROOT, output);
  if (
    relativePath === '' ||
    relativePath.startsWith('..') ||
    relativePath.includes(':')
  ) {
    throw new Error(`corpus path escapes root: ${sourcePath}`);
  }
  return output;
}

async function listSourceFiles(sourceRoot) {
  try {
    const output = [];
    await walk(sourceRoot, output);
    return output;
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') return [];
    throw error;
  }
}

async function assertSafeCorpusWriteTargets() {
  await mkdir(GOLDEN_CORPUS_ROOT, { recursive: true });
  await assertPlainDirectory(GOLDEN_CORPUS_ROOT);
  const sourceRoot = join(GOLDEN_CORPUS_ROOT, 'sources');
  await mkdir(sourceRoot, { recursive: true });
  await assertPlainDirectory(sourceRoot);
  const snapshotStat = await optionalLstat(GOLDEN_CORPUS_SNAPSHOT_PATH);
  if (
    snapshotStat &&
    (!snapshotStat.isFile() || snapshotStat.isSymbolicLink())
  ) {
    throw new Error('golden corpus snapshot write target must be a regular file');
  }
}

async function assertPlainDirectory(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`golden corpus write directory is unsafe: ${path}`);
  }
}

async function optionalLstat(path) {
  try {
    return await lstat(path);
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') return null;
    throw error;
  }
}

async function walk(directory, output) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`symbolic link is forbidden in corpus sources: ${absolute}`);
    }
    if (entry.isDirectory()) {
      await walk(absolute, output);
    } else if (entry.isFile()) {
      output.push(relative(GOLDEN_CORPUS_ROOT, absolute).replaceAll('\\', '/'));
    } else {
      throw new Error(`non-regular corpus source is forbidden: ${absolute}`);
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const { snapshot, sources } = await writeGoldenCorpusAssets();
  process.stdout.write(
    `generated ${snapshot.caseCount} cases in ${sources.size} source bundles (${snapshot.snapshotDigest})\n`
  );
}
