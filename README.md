Traefik Auth Server

A lightweight Fastify-based authentication server designed to integrate with Traefik and haproxy for secure access control. It provides HTTP Basic Authentication, IP whitelisting, and rate limiting, serving custom error pages for unauthorized or blocked requests.



Features





HTTP Basic Authentication:





Validates credentials using an .htpasswd file (bcrypt hashes).



Returns X-Forwarded-User header for authenticated users.



Serves 401.html for unauthorized requests.



IP Whitelisting:





Restricts access to IPs listed in whitelist.json.



Returns X-Whitelist-Allowed: true for allowed IPs.



Serves 403.html for non-whitelisted IPs.



Rate Limiting:





Limits authentication attempts to 5 per IP within a 1-hour window.



Blocks IPs exceeding the limit and serves 429.html.



Automatically clears expired blocks every 10 minutes.



Not Found Handler:





Returns 404.html for unmatched routes.



Custom Error Pages:





Serves HTML pages from the pages/ directory for errors (401, 403, 404, 429).



Traefik Integration:





Designed to work with Traefik (via metallb IP) and haproxy for routing and load balancing.



Supports X-Forwarded-For for accurate client IP detection.

Requirements





Node.js: v20 or higher.



Docker: For containerized deployment (optional).



Kubernetes: microk8s for deployment in a cluster (optional).



Traefik: v3.3.6 or compatible for ingress routing.



haproxy: For port forwarding (80, 443).

Installation

Local Setup





Clone the repository:

git clone https://github.com/mzezin/traefik-auth-server.git
cd traefik-auth-server



Install dependencies:

npm install



Create configuration files:





config/whitelist.json: List of allowed IPs (e.g., ["192.168.1.100"]).



config/.htpasswd: User credentials (e.g., admin:$2y$05$dVVI5kJOV7b3f9bh.GhXbOA2kKOIgCH3n4LgBrBz5BMcTLFTzP9jO).



Ensure pages/ contains 401.html, 403.html, 404.html, 429.html.



Compile TypeScript:

npx tsc



Start the server:

npm start

The server will listen on:





Port 3000: Authentication endpoint.



Port 3001: Whitelist-only endpoint.



Port 3002: Not Found endpoint.

Docker Setup





Pull the Docker image:

docker pull mzezin123/traefik-auth-server:latest



Run the container:

docker run -d \
  -p 3000:3000 \
  -p 3001:3001 \
  -p 3002:3002 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/pages:/app/pages \
  mzezin123/traefik-auth-server:latest



Access the server at http://localhost:3000, http://localhost:3001, http://localhost:3002

Testing with Postman

The project includes a Postman collection for testing the server’s functionality. The collection is located in the postman/ directory and covers:





HTTP Basic Authentication (valid and invalid credentials).



IP whitelisting (allowed and blocked IPs).



Rate limiting (429 after 5 failed attempts).



Error page responses (401, 403, 404, 429).

To use the collection:





Import postman/traefik-auth-server.postman_collection.json into Postman.



Configure the environment with your server’s URL (e.g., http://localhost:3000).



Run the tests to verify the server’s behavior.

Integration with Traefik and haproxy

This server is designed to run in a Kubernetes cluster (e.g., microk8s) with Traefik as the ingress controller and haproxy for external routing:





Traefik:





Deploy the server as a Kubernetes Deployment with a Service and IngressRoute.



Use metallb (IP pool 192.168.1.200–250) for Traefik’s ingress.



Configure Traefik to forward requests to the server’s ports (3000, 3001, 3002).



haproxy:





Set up port forwarding (80, 443) to Traefik’s metallb IP (192.168.1.200).



Ensure X-Forwarded-For headers are preserved for accurate IP detection.



Configuration:





Mount whitelist.json and .htpasswd as Kubernetes ConfigMap or Secret.



Store error pages (pages/) in the Docker image or a persistent volume.

See the Kubernetes deployment guide for detailed instructions (coming soon).

Contributing

Contributions are welcome! Please follow these steps:





Fork the repository.



Create a feature branch (git checkout -b feature/your-feature).



Commit your changes (git commit -m "Add your feature").



Push to the branch (git push origin feature/your-feature).



Open a Pull Request.

License

This project is licensed under the MIT License. See the LICENSE file for details.