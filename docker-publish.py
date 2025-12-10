#!/usr/bin/env python3
"""Script to build and publish Docker images for CrowdStrike Falcon MCP Server."""
import subprocess
import sys
import os
import argparse


def run_command(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=check)
    return result


def build_image(tag: str, dockerfile: str = "Dockerfile") -> None:
    """Build Docker image."""
    print(f"Building Docker image: {tag}")
    run_command([
        "docker", "build",
        "-t", tag,
        "-f", dockerfile,
        "."
    ])


def tag_image(source_tag: str, target_tag: str) -> None:
    """Tag Docker image."""
    print(f"Tagging {source_tag} as {target_tag}")
    run_command(["docker", "tag", source_tag, target_tag])


def push_image(tag: str) -> None:
    """Push Docker image to registry."""
    print(f"Pushing Docker image: {tag}")
    run_command(["docker", "push", tag])


def main():
    parser = argparse.ArgumentParser(description="Build and publish Docker images")
    parser.add_argument(
        "--registry",
        default=os.getenv("DOCKER_REGISTRY", "docker.io"),
        help="Docker registry (default: docker.io or DOCKER_REGISTRY env var)"
    )
    parser.add_argument(
        "--image-name",
        default=os.getenv("DOCKER_IMAGE_NAME", "crowdstrike-falcon-mcp"),
        help="Image name (default: crowdstrike-falcon-mcp or DOCKER_IMAGE_NAME env var)"
    )
    parser.add_argument(
        "--tag",
        default=os.getenv("IMAGE_TAG", "latest"),
        help="Image tag (default: latest or IMAGE_TAG env var)"
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="Only build, don't push"
    )
    parser.add_argument(
        "--dockerfile",
        default="Dockerfile",
        help="Dockerfile path (default: Dockerfile)"
    )
    
    args = parser.parse_args()
    
    # Construct full image tag
    if "/" in args.registry:
        # Registry already includes namespace
        full_tag = f"{args.registry}/{args.image_name}:{args.tag}"
    else:
        # Assume docker.io with username from env or use registry as-is
        username = os.getenv("DOCKER_USERNAME", "")
        if username:
            full_tag = f"{args.registry}/{username}/{args.image_name}:{args.tag}"
        else:
            full_tag = f"{args.registry}/{args.image_name}:{args.tag}"
    
    print(f"Full image tag: {full_tag}")
    
    # Build image
    build_image(full_tag, args.dockerfile)
    
    # Also tag as 'latest' if not already
    if args.tag != "latest":
        latest_tag = full_tag.rsplit(":", 1)[0] + ":latest"
        tag_image(full_tag, latest_tag)
        if not args.build_only:
            push_image(latest_tag)
    
    # Push image
    if not args.build_only:
        push_image(full_tag)
        print(f"Successfully published {full_tag}")
    else:
        print(f"Successfully built {full_tag} (not pushed)")


if __name__ == "__main__":
    main()

