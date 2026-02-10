param(
    [string]$Repo = "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF",
    [string]$File = "Meta-Llama-3.1-8B-Instruct-f32.gguf"
)

# Download a GGUF model file from Hugging Face.

$ErrorActionPreference = "Stop"

python -m pip install --upgrade huggingface_hub
python -c "from huggingface_hub import hf_hub_download; hf_hub_download(repo_id='$Repo', filename='$File', local_dir='models', local_dir_use_symlinks=False)"

$target = Join-Path "models" $File
if (-not (Test-Path $target)) {
    throw "Download did not create $target"
}
Write-Host "Downloaded to $target"
