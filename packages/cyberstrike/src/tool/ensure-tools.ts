import z from "zod"
import { Tool } from "./tool"

const TOOL_INSTALL_MAP: Record<string, { check: string; install: string; description: string }> = {
  nmap: { check: "nmap", install: "brew install nmap || apt-get install -y nmap", description: "Network scanner" },
  nuclei: {
    check: "nuclei",
    install: "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    description: "Vulnerability scanner",
  },
  ffuf: { check: "ffuf", install: "go install github.com/ffuf/ffuf/v2@latest", description: "Web fuzzer" },
  httpx: {
    check: "httpx",
    install: "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    description: "HTTP toolkit",
  },
  subfinder: {
    check: "subfinder",
    install: "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    description: "Subdomain discovery",
  },
  amass: {
    check: "amass",
    install: "go install -v github.com/owasp-amass/amass/v4/...@master",
    description: "Attack surface mapping",
  },
  waybackurls: {
    check: "waybackurls",
    install: "go install github.com/tomnomnom/waybackurls@latest",
    description: "Wayback Machine URL fetcher",
  },
  gau: { check: "gau", install: "go install github.com/lc/gau/v2/cmd/gau@latest", description: "URL aggregator" },
  hakrawler: {
    check: "hakrawler",
    install: "go install github.com/hakluke/hakrawler@latest",
    description: "Web crawler",
  },
  katana: {
    check: "katana",
    install: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    description: "Next-gen crawler",
  },
  dalfox: { check: "dalfox", install: "go install github.com/hahwul/dalfox/v2@latest", description: "XSS scanner" },
  sqlmap: { check: "sqlmap", install: "pip3 install sqlmap", description: "SQL injection tool" },
  nikto: {
    check: "nikto",
    install: "brew install nikto || apt-get install -y nikto",
    description: "Web server scanner",
  },
  wpscan: { check: "wpscan", install: "gem install wpscan || brew install wpscan", description: "WordPress scanner" },
  gospider: {
    check: "gospider",
    install: "go install github.com/jaeles-project/gospider@latest",
    description: "Web spidering",
  },
  arjun: { check: "arjun", install: "pip3 install arjun", description: "Parameter discovery" },
  paramspider: { check: "paramspider", install: "pip3 install paramspider", description: "Parameter mining" },
  commix: { check: "commix", install: "pip3 install commix", description: "Command injection" },
  ssrfmap: { check: "ssrfmap", install: "pip3 install ssrfmap", description: "SSRF exploitation" },
  nosqlmap: { check: "nosqlmap", install: "pip3 install nosqlmap", description: "NoSQL injection" },
  crlfuzz: {
    check: "crlfuzz",
    install: "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    description: "CRLF injection scanner",
  },
  gitdumper: { check: "git-dumper", install: "pip3 install git-dumper", description: "Git repository dumper" },
}

export const EnsureToolsTool = Tool.define("ensure_tools", {
  description:
    "Check if required security tools are installed and install missing ones. ONLY call this when the user has explicitly requested a pentest, vulnerability scan, or active security testing. NEVER call this for passive questions, code review, tech stack inquiries, or informational requests.",
  parameters: z.object({
    tools: z
      .array(z.string())
      .describe(`Tools to check/install. Available: ${Object.keys(TOOL_INSTALL_MAP).join(", ")}`),
  }),
  async execute(params) {
    // CERBERON SCRATCH PATCH (not upstream): the operator disabled runtime tool installation.
    // Upstream would shell out to brew/apt-get/go/pip here. Cerberon ships its scanner binaries in
    // the separate tools image, so nothing may be fetched at run time. Refuse and say so.
    const tools = params.tools ?? []
    const output = [
      `Tool installation is disabled on this instance. ${tools.length} requested tool(s) were not installed.`,
      "",
      ...tools.map((name) => `[DISABLED] ${name}: runtime installation is disabled; use the binaries shipped in the tools image`),
    ]
    return {
      title: `Tools: 0/${tools.length} installed (installation disabled)`,
      output: output.join("\n"),
      metadata: { installed: 0, failed: tools.length, disabled: true, requested: tools },
    }
  },
})
