#!/usr/bin/env pwsh
# Common PowerShell functions analogous to common.sh

function Get-RepoRoot {
    try {
        $result = git rev-parse --show-toplevel 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $result
        }
    } catch {
        # Git command failed
    }
    
    # Fall back to script location for non-git repos
    return (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
}

function Get-CurrentBranch {
    # Prefer the actual git branch whenever git is available.
    try {
        $result = git rev-parse --abbrev-ref HEAD 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $result
        }
    } catch {
        # Git command failed
    }
    
    # For non-git repos, fall back to the active feature override.
    if ($env:SPECIFY_FEATURE) {
        return $env:SPECIFY_FEATURE
    }

    # For non-git repos, try to find the latest feature directory
    $repoRoot = Get-RepoRoot
    $specsDir = Join-Path $repoRoot "specs"
    
    if (Test-Path $specsDir) {
        $latestFeature = ""
        $highest = 0
        
        Get-ChildItem -Path $specsDir -Directory | ForEach-Object {
            if ($_.Name -match '^(\d{3})-') {
                $num = [int]$matches[1]
                if ($num -gt $highest) {
                    $highest = $num
                    $latestFeature = $_.Name
                }
            }
        }
        
        if ($latestFeature) {
            return $latestFeature
        }
    }
    
    # Final fallback
    return "main"
}

function Get-LatestFeature {
    param([string]$SpecsDir)

    if (-not (Test-Path $SpecsDir)) {
        return $null
    }

    $latestFeature = $null
    $highest = -1

    Get-ChildItem -Path $SpecsDir -Directory | ForEach-Object {
        if ($_.Name -match '^(\d{3})-') {
            $num = [int]$matches[1]
            if ($num -gt $highest) {
                $highest = $num
                $latestFeature = $_.Name
            }
        }
    }

    return $latestFeature
}

function Get-ActiveFeatureFromAgents {
    param([string]$RepoRoot)

    $agentsPath = Join-Path $RepoRoot "AGENTS.md"
    if (-not (Test-Path $agentsPath)) {
        return $null
    }

    $match = Select-String -Path $agentsPath -Pattern 'Feature id:\s*`([^`]+)`' | Select-Object -First 1
    if ($match -and $match.Matches.Count -gt 0) {
        return $match.Matches[0].Groups[1].Value
    }

    return $null
}

function Get-FeatureFromBranch {
    param(
        [string]$Branch,
        [string]$SpecsDir
    )

    if (-not $Branch -or -not (Test-Path $SpecsDir)) {
        return $null
    }

    if ($Branch -match '^(\d{3}-.*)$') {
        $featureName = $matches[1]
        if (Test-Path (Join-Path $SpecsDir $featureName) -PathType Container) {
            return $featureName
        }
    }

    if ($Branch -match '^(feat|fix|refactor|release|hotfix)/(\d+)-') {
        $issueNumber = [int]$matches[2]
        $featurePrefix = '{0:000}' -f $issueNumber
        $matchedFeature = Get-ChildItem -Path $SpecsDir -Directory |
            Where-Object { $_.Name -match "^$featurePrefix-" } |
            Select-Object -First 1

        if ($matchedFeature) {
            return $matchedFeature.Name
        }
    }

    return $null
}

function Get-ActiveFeature {
    param(
        [string]$RepoRoot,
        [string]$CurrentBranch
    )

    $specsDir = Join-Path $RepoRoot "specs"

    if ($env:SPECIFY_FEATURE -and (Test-Path (Join-Path $specsDir $env:SPECIFY_FEATURE) -PathType Container)) {
        return $env:SPECIFY_FEATURE
    }

    $featureFromBranch = Get-FeatureFromBranch -Branch $CurrentBranch -SpecsDir $specsDir
    if ($featureFromBranch) {
        return $featureFromBranch
    }

    $featureFromAgents = Get-ActiveFeatureFromAgents -RepoRoot $RepoRoot
    if ($featureFromAgents -and (Test-Path (Join-Path $specsDir $featureFromAgents) -PathType Container)) {
        return $featureFromAgents
    }

    $latestFeature = Get-LatestFeature -SpecsDir $specsDir
    if ($latestFeature) {
        return $latestFeature
    }

    return $CurrentBranch
}

function Test-HasGit {
    try {
        git rev-parse --show-toplevel 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Test-FeatureBranch {
    param(
        [string]$Branch,
        [bool]$HasGit = $true
    )
    
    # For non-git repos, we can't enforce branch naming but still provide output
    if (-not $HasGit) {
        Write-Warning "[specify] Warning: Git repository not detected; skipped branch validation"
        return $true
    }
    
    if ($Branch -match '^[0-9]{3}-') {
        return $true
    }

    if ($Branch -in @('main', 'dev')) {
        return $true
    }

    if ($Branch -match '^(feat|fix|refactor|release|hotfix)/[0-9]+-[a-z0-9]+(?:-[a-z0-9]+)*$') {
        return $true
    }

    if ($env:SPECIFY_FEATURE) {
        return $true
    }

    if ($Branch -notmatch '^[0-9]{3}-') {
        Write-Output "ERROR: Not on a feature branch. Current branch: $Branch"
        Write-Output "Accepted branch patterns: feat/13-short-name, fix/13-short-name, refactor/13-short-name, release/13-short-name, hotfix/13-short-name, dev, main, or legacy 001-feature-name"
        return $false
    }
    return $true
}

function Get-FeatureDir {
    param([string]$RepoRoot, [string]$Branch)
    Join-Path $RepoRoot "specs/$Branch"
}

function Get-FeaturePathsEnv {
    $repoRoot = Get-RepoRoot
    $currentBranch = Get-CurrentBranch
    $hasGit = Test-HasGit
    $activeFeature = Get-ActiveFeature -RepoRoot $repoRoot -CurrentBranch $currentBranch
    $featureDir = Get-FeatureDir -RepoRoot $repoRoot -Branch $activeFeature
    
    [PSCustomObject]@{
        REPO_ROOT     = $repoRoot
        CURRENT_BRANCH = $currentBranch
        ACTIVE_FEATURE = $activeFeature
        HAS_GIT       = $hasGit
        FEATURE_DIR   = $featureDir
        FEATURE_SPEC  = Join-Path $featureDir 'spec.md'
        IMPL_PLAN     = Join-Path $featureDir 'plan.md'
        TASKS         = Join-Path $featureDir 'tasks.md'
        RESEARCH      = Join-Path $featureDir 'research.md'
        DATA_MODEL    = Join-Path $featureDir 'data-model.md'
        QUICKSTART    = Join-Path $featureDir 'quickstart.md'
        CONTRACTS_DIR = Join-Path $featureDir 'contracts'
    }
}

function Test-FileExists {
    param([string]$Path, [string]$Description)
    if (Test-Path -Path $Path -PathType Leaf) {
        Write-Output "  ✓ $Description"
        return $true
    } else {
        Write-Output "  ✗ $Description"
        return $false
    }
}

function Test-DirHasFiles {
    param([string]$Path, [string]$Description)
    if ((Test-Path -Path $Path -PathType Container) -and (Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | Select-Object -First 1)) {
        Write-Output "  ✓ $Description"
        return $true
    } else {
        Write-Output "  ✗ $Description"
        return $false
    }
}
