# Cloudflare + Google Security Command Center
> Monitor the network edge for threats to your Google Cloud assets

The Cloudflare + SCC integration runs inside Google App Engine's isolated runtime environment.

## Setup
[![Open in Cloud Shell](http://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/open?git_repo=https%3A%2F%2Fgithub.com%2Fcloudflare%2Fscc-cloudflare.git&page=shell)

```bash

# Clone this repo:
wget https://github.com/shagamemnon/cloudflare-scc/archive/v0.1.zip && unzip 0.1.zip && cd cloudflare-scc-0.1

# Install dependencies
npm install

# Initiate CLI
npm run cf:scc
```
