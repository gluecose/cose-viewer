# cose-viewer

An online decoder for [COSE](https://datatracker.ietf.org/doc/html/rfc8152) messages, currently limited to COSE_Sign1.

## Live preview

https://gluecose.github.io/cose-viewer/

## Development

1. Install [`npm`](https://nodejs.org/en/download)
2. Install project dependencies `npm install`
3. Run a build script `npm run build`, the files will appear in `dist` directory
4. Serve built files locally and access them via your browser, e.g. `python3 -m http.server 8080 --bind 127.0.0.1 --directory dist`

