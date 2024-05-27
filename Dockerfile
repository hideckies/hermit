FROM debian:latest

RUN apt-get update && apt-get install -y \
    git build-essential \
    && apt-get clean

# Clone Hermit project.
RUN git clone https://github.com/hideckies/hermit.git /hermit

# Build Hermit
RUN make server

WORKDIR /hermit

CMD ["hermit"]
