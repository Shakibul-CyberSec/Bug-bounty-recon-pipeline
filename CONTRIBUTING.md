# Contributing to Bug Bounty Recon Pipeline

First off, thank you for considering contributing to Bug Bounty Recon Pipeline! It's people like you that make this tool better for the entire security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Guidelines](#coding-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

### Our Pledge

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to a positive environment:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

Examples of unacceptable behavior:
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

## Getting Started

### Prerequisites

Before you begin, ensure you have:
- A GitHub account
- Git installed on your local machine
- Basic understanding of Bash scripting
- Familiarity with reconnaissance tools
- A Linux environment for testing

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/recon-pipeline.git
   cd recon-pipeline
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/recon-pipeline.git
   ```

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates.

When creating a bug report, include:
- **Clear title**: Descriptive and specific
- **Description**: Detailed explanation of the issue
- **Steps to reproduce**: Numbered steps to reproduce the behavior
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Environment**: OS, version, installed tools
- **Logs**: Relevant error messages or logs
- **Screenshots**: If applicable

Example:
```markdown
**Title**: DNS Resolution Fails with Custom Resolvers

**Description**: When using custom resolvers file, DNS resolution phase fails

**Steps to Reproduce**:
1. Run `./recon.sh -d example.com -r custom_resolvers.txt`
2. Wait for DNS resolution phase
3. Observe error

**Expected**: DNS resolution completes successfully
**Actual**: Script exits with error code 1

**Environment**:
- OS: Ubuntu 22.04
- Tool Version: v3.3
- Custom resolvers: 100 IPs

**Logs**:
```
[ERROR] DNS resolution failed: timeout
```
```

### Suggesting Enhancements

Enhancement suggestions are welcome! When suggesting:
- Use a clear and descriptive title
- Provide a detailed description of the enhancement
- Explain why this enhancement would be useful
- Include examples or mockups if possible

### Adding New Tools

Want to integrate a new reconnaissance tool? Great! Please:
1. Ensure the tool is actively maintained
2. Verify it adds unique value
3. Check licensing compatibility
4. Test thoroughly
5. Update documentation

### Improving Documentation

Documentation improvements are always appreciated:
- Fix typos and grammar
- Add clarifications
- Improve examples
- Add troubleshooting tips
- Translate to other languages

## Development Setup

### Setting Up Your Environment

1. **Install dependencies**:
   ```bash
   ./install.sh
   ```

2. **Set up test environment**:
   ```bash
   # Create test directory
   mkdir -p test_env
   cd test_env
   
   # Set up test domain (use your own domain!)
   echo "yourtestdomain.com" > test_domain.txt
   ```

3. **Run tests**:
   ```bash
   # Test basic functionality
   ./recon.sh -d yourtestdomain.com --dry-run
   ```

### Testing Your Changes

Before submitting a pull request:

1. **Syntax check**:
   ```bash
   bash -n recon.sh
   shellcheck recon.sh
   ```

2. **Functional testing**:
   ```bash
   # Test on a safe, authorized domain
   ./recon.sh -d yourtestdomain.com
   ```

3. **Test resume feature**:
   ```bash
   # Start scan
   ./recon.sh -d yourtestdomain.com
   
   # Interrupt it (Ctrl+C)
   
   # Resume
   ./recon.sh -d yourtestdomain.com --resume
   ```

4. **Test with different configurations**:
   ```bash
   # With custom wordlist
   ./recon.sh -d yourtestdomain.com -w custom_wordlist.txt
   
   # Without proxy
   ./recon.sh -d yourtestdomain.com --no-proxy
   ```

## Coding Guidelines

### Bash Style Guide

Follow these conventions for consistency:

1. **Naming Conventions**:
   ```bash
   # Variables: lowercase with underscores
   local_variable="value"
   GLOBAL_CONSTANT="VALUE"
   
   # Functions: lowercase with underscores
   my_function() {
       # function body
   }
   ```

2. **Indentation**:
   - Use 4 spaces (no tabs)
   - Indent function bodies
   - Indent conditional blocks

3. **Comments**:
   ```bash
   # Single line comment
   
   # Multi-line comment describing
   # complex logic or important details
   
   # Function description
   function_name() {
       # Brief explanation of what this function does
       local param=$1
       # Implementation
   }
   ```

4. **Error Handling**:
   ```bash
   # Always check command success
   if ! command; then
       echo -e "${RED}[!]${NC} Command failed"
       return 1
   fi
   
   # Use set -e for critical scripts
   set -e
   set -o pipefail
   ```

5. **Variable Quoting**:
   ```bash
   # Always quote variables
   local_var="$1"
   echo "$local_var"
   
   # Use curly braces for clarity
   echo "${variable}_suffix"
   ```

6. **Conditionals**:
   ```bash
   # Use [[ ]] instead of [ ]
   if [[ "$var" == "value" ]]; then
       # do something
   fi
   
   # Check if file exists
   if [[ -f "$file_path" ]]; then
       # process file
   fi
   ```

### Python Style Guide (for JSScan)

1. Follow PEP 8
2. Use type hints
3. Add docstrings
4. Keep functions focused
5. Use meaningful variable names

Example:
```python
def scan_file(file_path: str, aggressive: bool = False) -> List[SecretFinding]:
    """
    Scan a JavaScript file for secrets.
    
    Args:
        file_path: Path to the JavaScript file
        aggressive: Enable aggressive scanning mode
        
    Returns:
        List of discovered secrets
    """
    # Implementation
```

## Commit Messages

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding tests
- **chore**: Maintenance tasks

### Examples

```
feat(subdomain): Add support for subfinder v2.5

- Updated subfinder integration
- Added new configuration options
- Improved error handling

Closes #123
```

```
fix(dns): Resolve timeout issues with custom resolvers

Fixed a bug where custom resolvers caused timeouts during
DNS resolution phase. Now properly handles resolver failures
and falls back to default resolvers.

Fixes #456
```

```
docs(readme): Add troubleshooting section

Added common issues and solutions to README
```

## Pull Request Process

### Before Submitting

1. **Update your fork**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

3. **Make your changes**:
   - Follow coding guidelines
   - Add/update tests
   - Update documentation

4. **Test thoroughly**:
   - Run all tests
   - Test on multiple scenarios
   - Verify no regressions

5. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: Add awesome feature"
   ```

6. **Push to your fork**:
   ```bash
   git push origin feature/my-new-feature
   ```

### Submitting the PR

1. Go to your fork on GitHub
2. Click "Pull Request"
3. Select your feature branch
4. Fill out the PR template:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
- [ ] Tested on Ubuntu 22.04
- [ ] Tested with custom wordlists
- [ ] Tested resume feature
- [ ] No regression issues

## Checklist
- [ ] Code follows project guidelines
- [ ] Self-reviewed the code
- [ ] Commented complex logic
- [ ] Updated documentation
- [ ] No new warnings generated

## Related Issues
Fixes #123
Related to #456
```

### PR Review Process

1. **Automated checks**: CI/CD runs automatically
2. **Code review**: Maintainers review your code
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, PR will be merged

### After PR is Merged

1. **Delete your branch**:
   ```bash
   git branch -d feature/my-new-feature
   git push origin --delete feature/my-new-feature
   ```

2. **Update your main branch**:
   ```bash
   git checkout main
   git pull upstream main
   ```

## Recognition

Contributors will be:
- Listed in README.md
- Mentioned in release notes
- Credited in commit messages
- Appreciated by the community! 🙏

## Questions?

- Open an issue with the "question" label
- Join our discussions on GitHub
- Contact the maintainers

---

Thank you for contributing! Together, we make security testing better for everyone. 🚀
