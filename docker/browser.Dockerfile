FROM mcr.microsoft.com/playwright:v1.64.1-noble
RUN npm install --prefix /opt/playwright --ignore-scripts --no-audit --no-fund playwright@1.64.1
USER pwuser
CMD ["node", "/opt/playwright/node_modules/playwright/cli.js", "run-server", "--port", "3000", "--host", "0.0.0.0"]
