import {
  convertLatexToMarkup,
  convertLatexToMathMl,
} from '../src/public/mathlive-ssr';

//
// Validate that unsecure content is blocked
//
test('Unsecure Content', () => {
  expect(() =>
    convertLatexToMarkup('\\href{javascript:alert(1)}{Click me}')
  ).toThrow();

  expect(() =>
    convertLatexToMarkup('\\htmlData{><img/onerror=alert(1)"src=}{x}')
  ).toThrow();

  expect(
    convertLatexToMarkup('\\htmlData{x=" ><img/onerror=alert(1) src>}{x}')
  ).toMatch(
    '<span class="ML__latex"><span class="ML__strut" style="height:0.44em"></span><span class="ML__base"><span data-x="&quot; ><img/onerror=alert(1) src>"><span class="ML__mathit">x</span></span></span></span>'
  );

  // href via htmlData is blocked (unless it's a safe URL)
  expect(() =>
    convertLatexToMarkup('\\htmlData{href="javascript:alert(1)"}{x}')
  ).toThrow();

  expect(() =>
    convertLatexToMarkup('\\href{javascript:alert(1)}{x}')
  ).toThrow();

  expect(() =>
    convertLatexToMarkup(
      '\\href{data:application/json;base64,eyJmb28iOiJiYXIifQ==}{x}'
    )
  ).toThrow();

  expect(() =>
    convertLatexToMarkup(
      '\\href{\t\t\tj\ta\tv\ta\ts\tc\tr\ti\tp\tt:alert(1)}{x}'
    )
  ).toThrow();
});

//
// Text-content reflection must be escaped in both HTML and MathML output.
// (\text{}, \mbox{} accept arbitrary characters in their body.)
//
test('Text content escaping (XSS)', () => {
  const payload = '<img src=x onerror=alert(1)>';

  for (const cmd of ['\\text', '\\mbox']) {
    // HTML output: the body is rendered, with markup characters escaped.
    const html = convertLatexToMarkup(`${cmd}{${payload}}`);
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
    expect(html).toContain('&gt;');

    // MathML output: must never emit a raw tag.
    const mathml = convertLatexToMathMl(`${cmd}{${payload}}`);
    expect(mathml).not.toContain('<img');
  }

  // \text is serialized to MathML; confirm its body is escaped there too.
  expect(convertLatexToMathMl(`\\text{${payload}}`)).toContain('&lt;img');

  // A literal ampersand is escaped (and not double-escaped).
  expect(convertLatexToMarkup('\\text{a&b}')).toContain('a&amp;b');
  expect(convertLatexToMarkup('\\text{a&b}')).not.toContain('&amp;amp;');
  expect(convertLatexToMathMl('\\text{a&b}')).toContain('a&amp;b');

  // Literal `<`/`>` delimiters (e.g. \left< … \right>) are escaped in MathML.
  const delim = convertLatexToMathMl('\\left<x\\right>');
  expect(delim).not.toContain('<mo><');
  expect(delim).not.toContain('<mo>>');
  expect(delim).toContain('&lt;');
  expect(delim).toContain('&gt;');
});

//
// Secure Content
//
test('Secure Content', () => {
  // http and https protocols are allowed with \href
  expect(convertLatexToMarkup('\\href{http://example.com}{x}')).toMatch(
    '<span class="ML__latex"><span class="ML__strut" style="height:0.44em"></span><span class="ML__base"><span href="http://example.com"><span class="ML__mathit">x</span></span></span></span>'
  );

  // Gets turned into a data-onerror attribute, so safe
  expect(convertLatexToMarkup('\\htmlData{onerror=alert(1)}{x}')).toMatch(
    '<span class="ML__latex"><span class="ML__strut" style="height:0.44em"></span><span class="ML__base"><span data-onerror="alert(1)"><span class="ML__mathit">x</span></span></span></span>'
  );
});

//
// The `shadow` option of `\enclose` is placed inside the `style` attribute of
// the SVG overlay. A value with spaces or quotes must not be able to add
// attributes (such as an event handler) to the `<svg>` element.
//
test('Enclose shadow attribute injection', () => {
  const payload = String.raw`\enclose{horizontalstrike}[shadow="0) onload=window.pwned=1//"]{x}`;
  const markup = convertLatexToMarkup(payload);
  expect(markup).not.toMatch(/onload/);
  expect(markup).not.toMatch(/pwned/);
  // Nothing is emitted between the closing quote of `style` and the next
  // quoted attribute.
  expect(markup).toMatch(/<svg style="[^"]*" stroke-width="/);

  // A valid shadow is emitted inside the quoted `style` attribute.
  expect(
    convertLatexToMarkup(
      String.raw`\enclose{horizontalstrike}[shadow="1px 1px 2px red"]{x}`
    )
  ).toMatch(/<svg style="[^"]*filter:drop-shadow\(1px 1px 2px red\);" stroke-width="/);

  expect(
    convertLatexToMarkup(
      String.raw`\enclose{horizontalstrike}[shadow="1px 1px rgba(0, 0, 0, .5)"]{x}`
    )
  ).toMatch(/filter:drop-shadow\(1px 1px rgba\(0, 0, 0, .5\)\);" stroke-width="/);

  // `auto` uses the built-in preset and nothing else.
  const auto = convertLatexToMarkup(
    String.raw`\enclose{horizontalstrike}[shadow="auto"]{x}`
  );
  expect(auto).toMatch(/<svg style="[^"]*filter:drop-shadow\(0 0 .5px rgba\(255, 255, 255, .7\)\) drop-shadow\(1px 1px 2px #333\);" stroke-width="/);
  expect(auto).not.toMatch(/drop-shadow\(auto\)/);

  // Invalid shadows are dropped entirely.
  for (const bad of [
    'url(x)',
    '1px 1px red; background:url(x)',
    '1px',
    '1px 1px 1px 1px red',
    '1px 1px "red"',
    '1px 1px expression(1)',
    '1px 1px rgb(a) b',
  ]) {
    const m = convertLatexToMarkup(
      String.raw`\enclose{horizontalstrike}[shadow="` + bad + '"]{x}'
    );
    expect(m).not.toMatch(/filter:/);
    expect(m).toMatch(/<svg style="[^"]*" stroke-width="/);
  }
});
