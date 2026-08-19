import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  SAST_QUALIFICATION_NEGATIVE_KINDS,
  buildSastQualificationCorpusCase,
  buildSastQualificationCorpusSnapshot,
  buildSastQualificationPriorReleaseManifest,
  isSastQualificationPriorReleaseManifestValid
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
export const GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_PATH = join(
  GOLDEN_CORPUS_ROOT,
  'prior-release-must-detect.manifest.json'
);
export const GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_DIGEST =
  'sha256:6082809f216fda869790940a16cab9de32f6c5fcb4a6208611b51f65b79e1d17';

const GOLDEN_CORPUS_PROVENANCE = digestBoundReference(
  'sast-corpus-provenance://aegisai/t051/golden-v1',
  'aegisai-t051-golden-corpus-provenance-v1'
);
const PRIOR_RELEASE_REVISION = '0.9.0';
const PRIOR_RELEASE_PUBLISHED_AT = '2026-08-19T00:00:00.000Z';
const PRIOR_RELEASE_PROVENANCE = digestBoundReference(
  'sast-corpus-provenance://aegisai/t051/prior-release-import-v1',
  'aegisai-t051-prior-release-import-v1'
);

const NEGATIVE_KINDS_WITH_SANITIZER = [...SAST_QUALIFICATION_NEGATIVE_KINDS];
const NEGATIVE_KINDS_WITHOUT_SANITIZER = [
  'PATCHED',
  'SAFE_API',
  'COMMENT_OR_STRING',
  'GENERATED_OR_VENDOR'
];
const SECRET_NEGATIVE_KINDS = [
  'PATCHED',
  'SANITIZER',
  'SAFE_API',
  'GENERATED_OR_VENDOR'
];

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
  javaFamily('sql-injection', 'aegis.java.cwe-89.sql-injection', 'HIGH', true),
  javaFamily(
    'command-injection',
    'aegis.java.cwe-78.command-injection',
    'CRITICAL',
    true
  ),
  javaFamily('path-traversal', 'aegis.java.cwe-22.path-traversal', 'HIGH', true),
  javaFamily('ssrf', 'aegis.java.cwe-918.ssrf', 'HIGH'),
  javaFamily('ldap-injection', 'aegis.java.cwe-90.ldap-injection', 'HIGH', true),
  javaFamily('xpath-injection', 'aegis.java.cwe-643.xpath-injection', 'HIGH'),
  javaFamily(
    'unsafe-deserialization',
    'aegis.java.cwe-502.unsafe-deserialization',
    'CRITICAL'
  ),
  javaFamily('xxe', 'aegis.java.cwe-611.xxe', 'HIGH'),
  javaFamily('weak-crypto', 'aegis.java.cwe-327.weak-crypto', 'HIGH'),
  javaFamily('log-injection', 'aegis.java.cwe-117.log-injection', 'HIGH', true)
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

function createGoldenCorpusCaseAssets() {
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
  return { cases, sources };
}

export function createGoldenCorpusAssets(priorReleaseManifest) {
  if (!isSastQualificationPriorReleaseManifestValid(priorReleaseManifest, digest)) {
    throw new Error('invalid prior-release must-detect manifest');
  }
  const { cases, sources } = createGoldenCorpusCaseAssets();
  const snapshot = buildSastQualificationCorpusSnapshot(
    {
      revision: GOLDEN_CORPUS_REVISION,
      publishedAt: GOLDEN_CORPUS_PUBLISHED_AT,
      ownerRef: GOLDEN_CORPUS_OWNER,
      licenseExpression: GOLDEN_CORPUS_LICENSE,
      provenanceRef: GOLDEN_CORPUS_PROVENANCE,
      priorReleaseManifest,
      cases
    },
    digest
  );
  if (!snapshot) throw new Error('invalid generated golden corpus snapshot');
  return { snapshot, sources };
}

export function createInitialPriorReleaseManifest() {
  const { cases } = createGoldenCorpusCaseAssets();
  const bindings = cases
    .filter(
      (item) =>
        item.corpusClass === 'GOLDEN_POSITIVE' &&
        (item.severity === 'CRITICAL' || item.severity === 'HIGH')
    )
    .map((item) => ({
      caseId: item.caseId,
      caseDigest: item.caseDigest,
      caseKey: item.caseKey,
      caseRevision: item.caseRevision,
      ruleSemanticId: item.ruleSemanticId,
      ruleRevision: item.ruleRevision,
      severity: item.severity
    }));
  const manifest = buildSastQualificationPriorReleaseManifest(
    {
      releaseRevision: PRIOR_RELEASE_REVISION,
      publishedAt: PRIOR_RELEASE_PUBLISHED_AT,
      ownerRef: GOLDEN_CORPUS_OWNER,
      provenanceRef: PRIOR_RELEASE_PROVENANCE,
      bindings
    },
    digest
  );
  if (!manifest) throw new Error('invalid initial prior-release manifest');
  return manifest;
}

export async function writeGoldenCorpusAssets() {
  const writeContext = await assertSafeCorpusWriteTargets();
  const priorReleaseManifest = await readPriorReleaseManifestForGeneration(
    writeContext.root.canonical
  );
  const assets = createGoldenCorpusAssets(priorReleaseManifest);
  const expectedPaths = new Set(assets.sources.keys());
  const existingPaths = await listSourceFiles(
    join(GOLDEN_CORPUS_ROOT, 'sources'),
    writeContext.root.canonical
  );
  const stale = existingPaths.filter((path) => !expectedPaths.has(path));
  if (stale.length > 0) {
    throw new Error(`refusing to leave stale corpus sources: ${stale.join(', ')}`);
  }
  for (const [sourcePath, text] of assets.sources) {
    const output = safeCorpusPath(sourcePath);
    await writeStableRegularFile(output, text, writeContext.root.canonical);
  }
  await writeStableRegularFile(
    GOLDEN_CORPUS_SNAPSHOT_PATH,
    `${JSON.stringify(assets.snapshot, null, 2)}\n`,
    writeContext.root.canonical
  );
  await assertDirectoryStable(
    GOLDEN_CORPUS_ROOT,
    writeContext.root,
    'golden corpus root changed during generation'
  );
  await assertDirectoryStable(
    join(GOLDEN_CORPUS_ROOT, 'sources'),
    writeContext.sources,
    'golden corpus source root changed during generation'
  );
  return assets;
}

export async function initializePriorReleaseManifest() {
  await mkdir(GOLDEN_CORPUS_ROOT, { recursive: true });
  const root = await inspectPlainDirectory(GOLDEN_CORPUS_ROOT);
  if (await optionalLstat(GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_PATH)) {
    throw new Error(
      'refusing to overwrite immutable prior-release must-detect manifest'
    );
  }
  const manifest = createInitialPriorReleaseManifest();
  if (manifest.manifestDigest !== GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_DIGEST) {
    throw new Error('initial prior-release manifest does not match the reviewed digest');
  }
  let handle;
  try {
    handle = await open(
      GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_PATH,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600
    );
    await handle.writeFile(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle?.close().catch(() => undefined);
  }
  await assertDirectoryStable(
    GOLDEN_CORPUS_ROOT,
    root,
    'golden corpus root changed during manifest initialization'
  );
  return manifest;
}

function renderBundle(family, corpusClass) {
  if (
    !Array.isArray(family.negativeKinds) ||
    family.negativeKinds.length === 0 ||
    new Set(family.negativeKinds).size !== family.negativeKinds.length ||
    family.negativeKinds.some(
      (kind) => !SAST_QUALIFICATION_NEGATIVE_KINDS.includes(kind)
    )
  ) {
    throw new Error(`invalid negative-kind policy for ${family.slug}`);
  }
  const polarity = corpusClass === 'GOLDEN_POSITIVE' ? 'positive' : 'negative';
  const sourcePath = `sources/${family.language.toLowerCase()}/${family.slug}.${polarity}.bundle`;
  const lines = [];
  const blocks = [];
  for (let index = 0; index < 20; index += 1) {
    const ordinal = String(index + 1).padStart(3, '0');
    const negativeKind =
      corpusClass === 'GOLDEN_NEGATIVE'
        ? family.negativeKinds[index % family.negativeKinds.length]
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
  const body =
    polarity === 'positive' || negativeKind === 'GENERATED_OR_VENDOR'
      ? javaUnsafeBody(slug, input, ordinal)
      : negativeKind === 'COMMENT_OR_STRING'
        ? [
            ...javaUnsafeBody(slug, input, ordinal).map(
              (line) => `// documentation only: ${line}`
            ),
            `System.out.print(${input}.length());`
          ]
        : javaNegativeBody(slug, input, ordinal, negativeKind);
  return [
    `// ${anchor}`,
    ...(negativeKind ? [`// t051-negative-kind: ${negativeKind}`] : []),
    'package qualification.corpus;',
    `final class ${className} {`,
    `  void evaluate(String ${input}) throws Exception {`,
    ...body.map((line) => `    ${line}`),
    '  }',
    '}'
  ].join('\n');
}

function javaUnsafeBody(slug, input, ordinal) {
  switch (slug) {
    case 'sql-injection':
      return [
        `java.sql.Statement statement${ordinal} = null;`,
        `statement${ordinal}.executeQuery("SELECT * FROM account WHERE id='" + ${input} + "'");`
      ];
    case 'command-injection':
      return [`Runtime.getRuntime().exec("/usr/bin/tool " + ${input});`];
    case 'path-traversal':
      return [
        `java.nio.file.Path path${ordinal} = java.nio.file.Paths.get("/srv/data", ${input});`
      ];
    case 'ssrf':
      return [`new java.net.URL(${input}).openConnection();`];
    case 'ldap-injection':
      return [
        `javax.naming.directory.DirContext context${ordinal} = null;`,
        `context${ordinal}.search("ou=users", "(uid=" + ${input} + ")", null);`
      ];
    case 'xpath-injection':
      return [
        `javax.xml.xpath.XPath xpath${ordinal} = javax.xml.xpath.XPathFactory.newInstance().newXPath();`,
        `xpath${ordinal}.evaluate("//user[name='" + ${input} + "']", (Object) null);`
      ];
    case 'unsafe-deserialization':
      return [
        `java.io.ObjectInputStream stream${ordinal} = null;`,
        `stream${ordinal}.readObject();`
      ];
    case 'xxe':
      return [
        `javax.xml.parsers.DocumentBuilderFactory factory${ordinal} = javax.xml.parsers.DocumentBuilderFactory.newInstance();`,
        `factory${ordinal}.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(${input}.getBytes(java.nio.charset.StandardCharsets.UTF_8)));`
      ];
    case 'weak-crypto':
      return [
        `java.security.MessageDigest digest${ordinal} = java.security.MessageDigest.getInstance("MD5");`,
        `digest${ordinal}.digest(${input}.getBytes(java.nio.charset.StandardCharsets.UTF_8));`
      ];
    case 'log-injection':
      return [
        `System.getLogger("audit").log(System.Logger.Level.INFO, "user=" + ${input});`
      ];
    default:
      throw new Error(`unknown Java corpus family: ${slug}`);
  }
}

function javaNegativeBody(slug, input, ordinal, negativeKind) {
  if (!['PATCHED', 'SANITIZER', 'SAFE_API'].includes(negativeKind)) {
    throw new Error(`unsupported Java negative kind: ${slug}/${negativeKind}`);
  }
  switch (slug) {
    case 'sql-injection':
      if (negativeKind === 'PATCHED') {
        return [
          `long accountId${ordinal} = Long.parseLong(${input});`,
          `java.sql.Statement statement${ordinal} = null;`,
          `statement${ordinal}.executeQuery("SELECT * FROM account WHERE id=" + accountId${ordinal});`
        ];
      }
      if (negativeKind === 'SANITIZER') {
        return [
          `String sanitized${ordinal} = ${input}.replaceAll("[^0-9]", "");`,
          `java.sql.Statement statement${ordinal} = null;`,
          `statement${ordinal}.executeQuery("SELECT * FROM account WHERE id=" + sanitized${ordinal});`
        ];
      }
      return [
        `java.sql.PreparedStatement statement${ordinal} = null;`,
        `statement${ordinal}.setString(1, ${input});`,
        `statement${ordinal}.executeQuery();`
      ];
    case 'command-injection':
      if (negativeKind === 'PATCHED') {
        return [`new ProcessBuilder("/usr/bin/tool", "status").start();`];
      }
      if (negativeKind === 'SANITIZER') {
        return [
          `String sanitized${ordinal} = ${input}.replaceAll("[^A-Za-z0-9_-]", "");`,
          `new ProcessBuilder("/usr/bin/tool", sanitized${ordinal}).start();`
        ];
      }
      return [
        `java.util.List<String> allowed${ordinal} = java.util.List.of("status", "version");`,
        `new ProcessBuilder("/usr/bin/tool", allowed${ordinal}.contains(${input}) ? ${input} : "status").start();`
      ];
    case 'path-traversal':
      if (negativeKind === 'PATCHED') {
        return [
          `java.nio.file.Path path${ordinal} = java.nio.file.Path.of("/srv/data/fixed.txt");`,
          `java.nio.file.Files.readString(path${ordinal});`
        ];
      }
      if (negativeKind === 'SANITIZER') {
        return [
          `String sanitized${ordinal} = ${input}.replaceAll("[^A-Za-z0-9._-]", "");`,
          `java.nio.file.Path path${ordinal} = java.nio.file.Path.of("/srv/data").resolve(sanitized${ordinal});`,
          `java.nio.file.Files.readString(path${ordinal});`
        ];
      }
      return [
        `java.nio.file.Path root${ordinal} = java.nio.file.Path.of("/srv/data").normalize();`,
        `java.nio.file.Path path${ordinal} = root${ordinal}.resolve(${input}).normalize();`,
        `if (!path${ordinal}.startsWith(root${ordinal})) throw new SecurityException();`,
        `java.nio.file.Files.readString(path${ordinal});`
      ];
    case 'ssrf':
      return negativeKind === 'PATCHED'
        ? [
            `java.net.URI uri${ordinal} = java.net.URI.create("https://api.example.test/status");`,
            `uri${ordinal}.toURL().openConnection();`
          ]
        : [
            `java.net.URI uri${ordinal} = java.net.URI.create(${input});`,
            `if (!"https".equals(uri${ordinal}.getScheme()) || !"api.example.test".equals(uri${ordinal}.getHost())) throw new SecurityException();`,
            `uri${ordinal}.toURL().openConnection();`
          ];
    case 'ldap-injection':
      if (negativeKind === 'PATCHED') {
        return [
          `javax.naming.directory.DirContext context${ordinal} = null;`,
          `context${ordinal}.search("ou=users", "(uid=service-account)", null);`
        ];
      }
      if (negativeKind === 'SANITIZER') {
        return [
          `String sanitized${ordinal} = ${input}.replace("*", "\\\\2a").replace("(", "\\\\28").replace(")", "\\\\29");`,
          `javax.naming.directory.DirContext context${ordinal} = null;`,
          `context${ordinal}.search("ou=users", "(uid=" + sanitized${ordinal} + ")", null);`
        ];
      }
      return [
        `javax.naming.directory.DirContext context${ordinal} = null;`,
        `context${ordinal}.search("ou=users", "(uid={0})", new Object[] { ${input} }, null);`
      ];
    case 'xpath-injection':
      if (negativeKind === 'PATCHED') {
        return [
          `javax.xml.xpath.XPath xpath${ordinal} = javax.xml.xpath.XPathFactory.newInstance().newXPath();`,
          `xpath${ordinal}.evaluate("//user[@active='true']", (Object) null);`
        ];
      }
      return [
        `javax.xml.xpath.XPath xpath${ordinal} = javax.xml.xpath.XPathFactory.newInstance().newXPath();`,
        `xpath${ordinal}.setXPathVariableResolver(name -> ${input});`,
        `xpath${ordinal}.evaluate("//user[name=$name]", (Object) null);`
      ];
    case 'unsafe-deserialization':
      return negativeKind === 'PATCHED'
        ? [
            `java.io.ObjectInputStream stream${ordinal} = null;`,
            `stream${ordinal}.setObjectInputFilter(java.io.ObjectInputFilter.Config.createFilter("java.base/*;!*"));`,
            `stream${ordinal}.readObject();`
          ]
        : [
            `java.io.DataInputStream stream${ordinal} = null;`,
            `String value${ordinal} = stream${ordinal}.readUTF();`
          ];
    case 'xxe':
      if (negativeKind === 'PATCHED') {
        return [
          `javax.xml.parsers.DocumentBuilderFactory factory${ordinal} = javax.xml.parsers.DocumentBuilderFactory.newInstance();`,
          `factory${ordinal}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`,
          `factory${ordinal}.setExpandEntityReferences(false);`,
          `factory${ordinal}.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(${input}.getBytes(java.nio.charset.StandardCharsets.UTF_8)));`
        ];
      }
      return [
        `javax.xml.parsers.SAXParserFactory factory${ordinal} = javax.xml.parsers.SAXParserFactory.newInstance();`,
        `factory${ordinal}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`,
        `factory${ordinal}.newSAXParser().parse(new java.io.ByteArrayInputStream(${input}.getBytes(java.nio.charset.StandardCharsets.UTF_8)), new org.xml.sax.helpers.DefaultHandler());`
      ];
    case 'weak-crypto':
      return negativeKind === 'PATCHED'
        ? [
            `java.security.MessageDigest digest${ordinal} = java.security.MessageDigest.getInstance("SHA-256");`,
            `digest${ordinal}.digest(${input}.getBytes(java.nio.charset.StandardCharsets.UTF_8));`
          ]
        : [
            `javax.crypto.Mac mac${ordinal} = javax.crypto.Mac.getInstance("HmacSHA256");`,
            `byte[] value${ordinal} = ${input}.getBytes(java.nio.charset.StandardCharsets.UTF_8);`,
            `mac${ordinal}.doFinal(value${ordinal});`
          ];
    case 'log-injection':
      if (negativeKind === 'PATCHED') {
        return [
          `String identifier${ordinal} = Integer.toHexString(${input}.hashCode());`,
          `System.getLogger("audit").log(System.Logger.Level.INFO, "user-id=" + identifier${ordinal});`
        ];
      }
      if (negativeKind === 'SANITIZER') {
        return [
          `String sanitized${ordinal} = ${input}.replace("\\r", "_").replace("\\n", "_");`,
          `System.getLogger("audit").log(System.Logger.Level.INFO, "user=" + sanitized${ordinal});`
        ];
      }
      return [
        `java.util.logging.LogRecord record${ordinal} = new java.util.logging.LogRecord(java.util.logging.Level.INFO, "authenticated-user");`,
        `record${ordinal}.setParameters(new Object[] { Integer.toHexString(${input}.hashCode()) });`,
        `java.util.logging.Logger.getLogger("audit").log(record${ordinal});`
      ];
    default:
      throw new Error(`unknown Java corpus family: ${slug}`);
  }
}

function commonSnippet(slug, polarity, ordinal, anchor, negativeKind) {
  const positive = polarity === 'positive';
  const generated = negativeKind === 'GENERATED_OR_VENDOR';
  switch (slug) {
    case 'log4shell-maven':
      return mavenSnippet(
        anchor,
        'org.apache.logging.log4j',
        'log4j-core',
        '2.14.1',
        '2.17.1',
        positive ? null : negativeKind
      );
    case 'jackson-maven':
      return mavenSnippet(
        anchor,
        'com.fasterxml.jackson.core',
        'jackson-databind',
        '2.9.9',
        '2.15.4',
        positive ? null : negativeKind
      );
    case 'spring-gradle':
      if (positive || generated) {
        return [
          `// ${anchor}`,
          ...(negativeKind ? [`// t051-negative-kind: ${negativeKind}`] : []),
          'dependencies {',
          '  implementation("org.springframework:spring-core:5.3.17")',
          '}'
        ].join('\n');
      }
      if (negativeKind === 'COMMENT_OR_STRING') {
        return [
          `// ${anchor}`,
          '// t051-negative-kind: COMMENT_OR_STRING',
          '// documentation only: implementation("org.springframework:spring-core:5.3.17")'
        ].join('\n');
      }
      if (negativeKind === 'SAFE_API') {
        return [
          `// ${anchor}`,
          '// t051-negative-kind: SAFE_API',
          '// Platform JDK implementation; no Spring dependency is declared.',
          'dependencies {}'
        ].join('\n');
      }
      return [
        `// ${anchor}`,
        '// t051-negative-kind: PATCHED',
        'dependencies {',
        '  implementation("org.springframework:spring-core:5.3.20")',
        '}'
      ].join('\n');
    case 'lodash-npm':
      if (positive) {
        return JSON.stringify(
          {
            name: `t051-${anchor.replaceAll('.', '-')}`,
            version: '1.0.0',
            description: anchor,
            dependencies: { lodash: '4.17.20' }
          },
          null,
          2
        );
      }
      if (generated) {
        return JSON.stringify(
          {
            name: `t051-${anchor.replaceAll('.', '-')}`,
            version: '1.0.0',
            qualificationAnchor: anchor,
            qualificationNegativeKind: negativeKind,
            dependencies: { lodash: '4.17.20' }
          },
          null,
          2
        );
      }
      return JSON.stringify(
        {
          name: `t051-${anchor.replaceAll('.', '-')}`,
          version: '1.0.0',
          qualificationAnchor: anchor,
          qualificationNegativeKind: negativeKind,
          ...(negativeKind === 'COMMENT_OR_STRING'
            ? { description: 'documentation only: lodash 4.17.20' }
            : negativeKind === 'SAFE_API'
              ? { safeAlternative: 'ECMAScript standard library', dependencies: {} }
              : { dependencies: { lodash: '4.17.21' } })
        },
        null,
        2
      );
    case 'aws-access-key':
      return envSecretSnippet(
        anchor,
        'AWS_ACCESS_KEY_ID',
        `AKIA${syntheticToken(ordinal, 16, 'A')}`,
        positive ? null : negativeKind
      );
    case 'github-token':
      return envSecretSnippet(
        anchor,
        'GITHUB_TOKEN',
        `ghp_${syntheticToken(ordinal, 36, 'g')}`,
        positive ? null : negativeKind
      );
    case 'private-key':
      return envSecretSnippet(
        anchor,
        'PRIVATE_KEY',
        `-----BEGIN PRIVATE KEY-----${syntheticToken(ordinal, 48, 'K')}-----END PRIVATE KEY-----`,
        positive ? null : negativeKind
      );
    case 'docker-root-user':
      if (positive || generated) {
        return [
          `# ${anchor}`,
          ...(negativeKind ? [`# t051-negative-kind: ${negativeKind}`] : []),
          'FROM scratch',
          'USER root',
          'ENTRYPOINT ["/app"]'
        ].join('\n');
      }
      if (negativeKind === 'COMMENT_OR_STRING') {
        return [
          `# ${anchor}`,
          '# t051-negative-kind: COMMENT_OR_STRING',
          'FROM scratch',
          '# documentation only: USER root',
          'USER 65532'
        ].join('\n');
      }
      if (negativeKind === 'SAFE_API') {
        return [
          `# ${anchor}`,
          '# t051-negative-kind: SAFE_API',
          'FROM gcr.io/distroless/static-debian12:nonroot',
          'ENTRYPOINT ["/app"]'
        ].join('\n');
      }
      return [
        `# ${anchor}`,
        '# t051-negative-kind: PATCHED',
        'FROM scratch',
        'USER 65532',
        'ENTRYPOINT ["/app"]'
      ].join('\n');
    case 'terraform-public-storage':
      if (positive || generated) {
        return [
          `# ${anchor}`,
          ...(negativeKind ? [`# t051-negative-kind: ${negativeKind}`] : []),
          `resource "aws_s3_bucket" "case_${ordinal}" {`,
          `  bucket = "t051-case-${ordinal}"`,
          '  acl = "public-read"',
          '}'
        ].join('\n');
      }
      if (negativeKind === 'COMMENT_OR_STRING') {
        return [
          `# ${anchor}`,
          '# t051-negative-kind: COMMENT_OR_STRING',
          `resource "aws_s3_bucket" "case_${ordinal}" {`,
          `  bucket = "t051-case-${ordinal}"`,
          '  # documentation only: acl = "public-read"',
          '  acl = "private"',
          '}'
        ].join('\n');
      }
      if (negativeKind === 'SAFE_API') {
        return [
          `# ${anchor}`,
          '# t051-negative-kind: SAFE_API',
          `resource "aws_s3_bucket_public_access_block" "case_${ordinal}" {`,
          `  bucket = "t051-case-${ordinal}"`,
          '  block_public_acls = true',
          '  block_public_policy = true',
          '  ignore_public_acls = true',
          '  restrict_public_buckets = true',
          '}'
        ].join('\n');
      }
      return [
        `# ${anchor}`,
        '# t051-negative-kind: PATCHED',
        `resource "aws_s3_bucket" "case_${ordinal}" {`,
        `  bucket = "t051-case-${ordinal}"`,
        '  acl = "private"',
        '}'
      ].join('\n');
    case 'kubernetes-privileged':
      if (positive || generated) {
        return kubernetesSnippet(anchor, ordinal, negativeKind, [
          '            privileged: true'
        ]);
      }
      if (negativeKind === 'COMMENT_OR_STRING') {
        return kubernetesSnippet(anchor, ordinal, negativeKind, [
          '            # documentation only: privileged: true',
          '            privileged: false'
        ]);
      }
      if (negativeKind === 'SAFE_API') {
        return kubernetesSnippet(anchor, ordinal, negativeKind, [
          '            runAsNonRoot: true',
          '            readOnlyRootFilesystem: true',
          '            allowPrivilegeEscalation: false',
          '            capabilities:',
          '              drop: ["ALL"]'
        ]);
      }
      return kubernetesSnippet(anchor, ordinal, negativeKind, [
        '            privileged: false',
        '            runAsNonRoot: true',
        '            allowPrivilegeEscalation: false'
      ]);
    default:
      throw new Error(`unknown common corpus family: ${slug}`);
  }
}

function mavenSnippet(
  anchor,
  groupId,
  artifactId,
  vulnerableVersion,
  patchedVersion,
  negativeKind
) {
  const dependency =
    negativeKind !== 'SAFE_API' && negativeKind !== 'COMMENT_OR_STRING';
  const version = negativeKind === 'PATCHED' ? patchedVersion : vulnerableVersion;
  return [
    `<!-- ${anchor} -->`,
    ...(negativeKind ? [`<!-- t051-negative-kind: ${negativeKind} -->`] : []),
    '<project xmlns="http://maven.apache.org/POM/4.0.0">',
    '  <modelVersion>4.0.0</modelVersion>',
    '  <groupId>test.aegis.qualification</groupId>',
    `  <artifactId>${anchor.replaceAll('.', '-')}</artifactId>`,
    '  <version>1.0.0</version>',
    ...(negativeKind === 'COMMENT_OR_STRING'
      ? [`  <!-- documentation only: ${groupId}:${artifactId}:${vulnerableVersion} -->`]
      : dependency
        ? [
          '  <dependencies>',
          '    <dependency>',
          `      <groupId>${groupId}</groupId>`,
          `      <artifactId>${artifactId}</artifactId>`,
          `      <version>${version}</version>`,
          '    </dependency>',
          '  </dependencies>'
          ]
        : ['  <!-- SAFE_API: platform standard library; vulnerable dependency absent -->']),
    '</project>'
  ].join('\n');
}

function envSecretSnippet(anchor, key, unsafeValue, negativeKind) {
  const value =
    negativeKind === 'PATCHED'
      ? `${key}_ROTATED=true`
      : negativeKind === 'SANITIZER'
        ? `${key}=[REDACTED]`
        : negativeKind === 'SAFE_API'
          ? `${key}_REF=secret://qualification/${key.toLowerCase()}`
          : `${key}=${unsafeValue}`;
  return [
    `# ${anchor}`,
    ...(negativeKind ? [`# t051-negative-kind: ${negativeKind}`] : []),
    value,
    'QUALIFICATION_FIXTURE=true'
  ].join('\n');
}

function kubernetesSnippet(anchor, ordinal, negativeKind, securityContext) {
  return [
    `# ${anchor}`,
    ...(negativeKind ? [`# t051-negative-kind: ${negativeKind}`] : []),
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
    ...securityContext
  ].join('\n');
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

function javaFamily(slug, ruleSemanticId, severity, sanitizerApplicable = false) {
  return {
    slug,
    ruleSemanticId,
    severity,
    capability: 'SAST',
    scanner: 'OPENGREP',
    language: 'JAVA',
    negativeKinds: sanitizerApplicable
      ? NEGATIVE_KINDS_WITH_SANITIZER
      : NEGATIVE_KINDS_WITHOUT_SANITIZER
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
    language: 'COMMON',
    negativeKinds:
      capability === 'SECRET_DETECTION'
        ? SECRET_NEGATIVE_KINDS
        : NEGATIVE_KINDS_WITHOUT_SANITIZER
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

async function readPriorReleaseManifestForGeneration(canonicalRoot) {
  const stat = await optionalLstat(GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_PATH);
  if (!stat || !stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('prior-release must-detect manifest must be a regular file');
  }
  const text = (
    await readStableRegularFile(
      GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_PATH,
      canonicalRoot
    )
  ).toString('utf8');
  if (
    text.startsWith('\uFEFF') ||
    text.includes('\r') ||
    !text.endsWith('\n') ||
    text !== text.normalize('NFC')
  ) {
    throw new Error('prior-release must-detect manifest is not canonical UTF-8/LF');
  }
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch {
    throw new Error('prior-release must-detect manifest is invalid JSON');
  }
  if (
    !isSastQualificationPriorReleaseManifestValid(manifest, digest) ||
    manifest.manifestDigest !== GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_DIGEST ||
    text !== `${JSON.stringify(manifest, null, 2)}\n`
  ) {
    throw new Error('prior-release must-detect manifest is invalid or noncanonical');
  }
  return manifest;
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

async function listSourceFiles(sourceRoot, canonicalRoot) {
  try {
    const output = [];
    await walk(sourceRoot, output, canonicalRoot);
    return output;
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') return [];
    throw error;
  }
}

async function assertSafeCorpusWriteTargets() {
  const root = await inspectPlainDirectory(GOLDEN_CORPUS_ROOT);
  const sourceRoot = join(GOLDEN_CORPUS_ROOT, 'sources');
  const sources = await inspectPlainDirectory(sourceRoot, root.canonical);
  const snapshotStat = await optionalLstat(GOLDEN_CORPUS_SNAPSHOT_PATH);
  if (
    !snapshotStat ||
    !snapshotStat.isFile() ||
    snapshotStat.isSymbolicLink()
  ) {
    throw new Error('golden corpus snapshot write target must be a regular file');
  }
  const manifestStat = await optionalLstat(
    GOLDEN_CORPUS_PRIOR_RELEASE_MANIFEST_PATH
  );
  if (!manifestStat || !manifestStat.isFile() || manifestStat.isSymbolicLink()) {
    throw new Error('prior-release manifest write dependency must be a regular file');
  }
  return { root, sources };
}

async function inspectPlainDirectory(path, canonicalRoot) {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`golden corpus write directory is unsafe: ${path}`);
  }
  const canonical = await realpath(path);
  if (canonicalRoot) ensureWithin(canonicalRoot, canonical, path, true);
  return { stat, canonical };
}

async function assertDirectoryStable(path, expected, reason) {
  const current = await inspectPlainDirectory(path);
  if (
    current.canonical !== expected.canonical ||
    !sameNodeIdentity(current.stat, expected.stat)
  ) {
    throw new Error(reason);
  }
}

async function readStableRegularFile(path, canonicalRoot) {
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error(`golden corpus read target is unsafe: ${path}`);
  }
  const canonicalBefore = await realpath(path);
  ensureWithin(canonicalRoot, canonicalBefore, path);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
    );
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameStableIdentity(before, opened)) {
      throw new Error(`golden corpus read target changed before open: ${path}`);
    }
    const value = await handle.readFile();
    const openedAfter = await handle.stat({ bigint: true });
    const after = await lstat(path, { bigint: true });
    const canonicalAfter = await realpath(path);
    ensureWithin(canonicalRoot, canonicalAfter, path);
    if (
      !sameStableIdentity(opened, openedAfter) ||
      !sameStableIdentity(before, after) ||
      canonicalAfter !== canonicalBefore
    ) {
      throw new Error(`golden corpus read target changed during read: ${path}`);
    }
    return value;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function writeStableRegularFile(path, value, canonicalRoot) {
  const parentPath = dirname(path);
  const parent = await inspectPlainDirectory(parentPath, canonicalRoot);
  const before = await lstat(path, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error(`golden corpus write target is unsafe: ${path}`);
  }
  const canonicalBefore = await realpath(path);
  ensureWithin(canonicalRoot, canonicalBefore, path);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0)
    );
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || !sameNodeIdentity(before, opened)) {
      throw new Error(`golden corpus write target changed before open: ${path}`);
    }
    await handle.truncate(0);
    await handle.writeFile(value, { encoding: 'utf8' });
    await handle.sync();
    const openedAfter = await handle.stat({ bigint: true });
    const after = await lstat(path, { bigint: true });
    const canonicalAfter = await realpath(path);
    ensureWithin(canonicalRoot, canonicalAfter, path);
    if (
      !sameNodeIdentity(opened, openedAfter) ||
      !sameNodeIdentity(before, after) ||
      canonicalAfter !== canonicalBefore
    ) {
      throw new Error(`golden corpus write target changed during write: ${path}`);
    }
  } finally {
    await handle?.close().catch(() => undefined);
  }
  await assertDirectoryStable(
    parentPath,
    parent,
    `golden corpus write directory changed during write: ${parentPath}`
  );
}

function ensureWithin(root, candidate, label, allowRoot = false) {
  const relation = relative(root, candidate);
  if (
    (!allowRoot && relation === '') ||
    relation.startsWith('..') ||
    relation.includes(':')
  ) {
    throw new Error(`golden corpus path escapes root: ${label}`);
  }
}

function sameNodeIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink
  );
}

function sameStableIdentity(left, right) {
  return (
    sameNodeIdentity(left, right) &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

async function optionalLstat(path) {
  try {
    return await lstat(path, { bigint: true });
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') return null;
    throw error;
  }
}

async function walk(directory, output, canonicalRoot) {
  const inspected = await inspectPlainDirectory(directory, canonicalRoot);
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = join(directory, entry.name);
    const stat = await lstat(absolute, { bigint: true });
    if (entry.isSymbolicLink() || stat.isSymbolicLink()) {
      throw new Error(`symbolic link is forbidden in corpus sources: ${absolute}`);
    }
    if (entry.isDirectory() && stat.isDirectory()) {
      await walk(absolute, output, canonicalRoot);
    } else if (entry.isFile() && stat.isFile()) {
      ensureWithin(canonicalRoot, await realpath(absolute), absolute);
      output.push(relative(GOLDEN_CORPUS_ROOT, absolute).replaceAll('\\', '/'));
    } else {
      throw new Error(`non-regular corpus source is forbidden: ${absolute}`);
    }
  }
  await assertDirectoryStable(
    directory,
    inspected,
    `golden corpus source directory changed during enumeration: ${directory}`
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.includes('--initialize-prior-release-manifest')) {
    const manifest = await initializePriorReleaseManifest();
    process.stdout.write(
      `initialized ${manifest.caseCount} immutable prior-release cases (${manifest.manifestDigest})\n`
    );
  } else {
    const { snapshot, sources } = await writeGoldenCorpusAssets();
    process.stdout.write(
      `generated ${snapshot.caseCount} cases in ${sources.size} source bundles (${snapshot.snapshotDigest})\n`
    );
  }
}
