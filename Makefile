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
shell:
	sudo $(DOCKER) exec -it $(CONTAINER) bash
