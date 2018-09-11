# Cloudflare + Google Security Command Center
> Monitor the network edge for threats to your Google Cloud assets

The Cloudflare + SCC integration runs inside Google App Engine's isolated runtime environment.

## Setup

```bash

# Remove previous versions
rm -rf cloudflare-scc-master

# Clone this repo:
curl -LO "https://github.com/shagamemnon/cloudflare-scc/archive/master.zip" && unzip master.zip && cd cloudflare-scc-master

# Install dependencies
npm install

# Initiate CLI
npm run cf:scc
```
