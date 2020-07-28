Mercury
=====================================
Mercury is a client/server implementation of a state chain ([whitepaper](doc/statechains.md)).

Running / Building
-------

Run steps:
To run the software, use Docker image from DockerHub.

1. Download and start: ```docker run --rm -it -p 8000:8000 commerceblock/mercury server```
2. Test: ```curl -vk localhost:8000/ping```

Build steps:
To build the software use Dockerfile provided.

1. Clone repo
2. Build: ```cd mercury && docker build -t commerceblock/mercury:my_build .```
3. Run: ```docker run --rm -it -p 8000:8000 commerceblock/mercury server```
4. Test: ```curl -vk localhost:8000/ping```
