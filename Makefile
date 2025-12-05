# ===== Config =====
IMAGE      = ciphergate-agent
CONTAINER  = ciphergate-agent
DOCKERFILE_PATH = ./docker
DOCKER    = docker

# ===== Phony targets =====
.PHONY: all build up down clean fclean re logs shell prune

# Default: just build the image
all: build

# Build the Docker image
build:
	sudo $(DOCKER) build -t $(IMAGE) $(DOCKERFILE_PATH)

# Run the container with tshark permissions
up:
	$(MAKE) build
	-sudo $(DOCKER) stop $(CONTAINER)
	-sudo $(DOCKER) rm $(CONTAINER)
	sudo $(DOCKER) run -it \
		--cap-add=NET_ADMIN \
		--cap-add=NET_RAW \
		--network=host \
		--name $(CONTAINER) \
		$(IMAGE)

# Stop & remove the container
down:
	-sudo $(DOCKER) stop $(CONTAINER)
	-sudo $(DOCKER) rm $(CONTAINER)

# Alias: clean = remove container
clean: down

# Full clean: container + image + prune
fclean: clean
	-sudo $(DOCKER) rmi $(IMAGE)
	-sudo $(DOCKER) system prune -f

# Rebuild everything from scratch
re: fclean all

# Follow container logs
logs:
	sudo $(DOCKER) logs -f $(CONTAINER)

# Get a shell inside the running container
capture:
	@echo "=== Running tshark inside container (10 frames -> slim CSV) ==="
	$(DOCKER) exec $(CONTAINER) sh -c '\
	  rm -f /data/packets.csv; \
	  tshark -i any -c 10 \
	    -T fields -E header=y -E separator=, -E quote=d \
	    -e frame.number \
	    -e frame.time_epoch \
	    -e frame.len \
	    -e ip.src \
	    -e ip.dst \
	    -e tcp.srcport \
	    -e tcp.dstport \
	    -e udp.srcport \
	    -e udp.dstport \
	    -e _ws.col.Protocol \
	    -e dns.qry.name \
	    -e dns.qry.type \
	    > /data/packets.csv'

	@echo "=== Copying CSV to host (for testing) ==="
	$(DOCKER) cp $(CONTAINER):/data/packets.csv ./packets.csv

	@echo "=== Deleting CSV inside container (cleanup) ==="
	$(DOCKER) exec $(CONTAINER) sh -c 'rm -f /data/tshark_raw.txt'

	@echo "=== Done. Slim CSV available at ./packets.csv ==="
