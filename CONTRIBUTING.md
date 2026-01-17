# Contributing to Face Recognition Attendance System

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## Getting Started

### Prerequisites

- **Android Studio Giraffe (2022.3.1)** or later
- **JDK 17** (Oracle JDK or OpenJDK)
- **Android SDK 34**
- **Git** for version control
- **Firebase project** (for backend services)

### Setup Development Environment

1. **Fork the repository**
   ```bash
   # Click "Fork" button on GitHub
   git clone https://github.com/YOUR_USERNAME/face-recognition-attendance-system.git
   cd face-recognition-attendance-system
   ```

2. **Configure Firebase**
   ```bash
   cp local.properties.example local.properties
   # Edit local.properties with your Firebase credentials
   ```

3. **Install Git hooks**
   ```bash
   cp pre-commit .git/hooks/pre-commit
   chmod +x .git/hooks/pre-commit
   ```

4. **Sync and build**
   ```bash
   ./gradlew build
   ```

## Development Workflow

### 1. Create Feature Branch

```bash
# Update your fork
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feat/your-feature-name
```

**Branch naming conventions:**
- `feat/feature-name` - New features
- `fix/bug-description` - Bug fixes
- `docs/what-changed` - Documentation
- `refactor/component-name` - Code refactoring
- `test/test-description` - Adding tests
- `chore/task-name` - Maintenance tasks

### 2. Make Changes

- Follow coding standards (see below)
- Write clean, self-documenting code
- Add tests for new functionality
- Update documentation as needed

### 3. Commit Changes

Use **Conventional Commits** format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes
- `security`: Security fixes

**Examples:**
```bash
git commit -m "feat(auth): add biometric authentication"
git commit -m "fix(camera): resolve face detection crash on Android 11"
git commit -m "docs(readme): update installation instructions"
```

### 4. Push and Create PR

```bash
git push origin feat/your-feature-name
```

Then create a Pull Request on GitHub.

## Coding Standards

### Clean Architecture

Follow the three-layer architecture:

```
Presentation → Domain → Data
```

- **Presentation**: Activities, Fragments, ViewModels, UI components
- **Domain**: Models, Use Cases, Repository interfaces
- **Data**: Repository implementations, Room database, Firebase

### MVVM Pattern

- Use `ViewModel` for business logic
- Use `LiveData` or `StateFlow` for reactive UI updates
- Keep Activities/Fragments thin - only UI logic

### Code Style

**Follow Ktlint and Detekt rules:**

```bash
# Check formatting
./gradlew ktlintCheck

# Auto-format
./gradlew ktlintFormat

# Run static analysis
./gradlew detekt
```

**Best Practices:**

1. **Immutability by default**
   ```kotlin
   // Good
   val name: String = "John"
   
   // Avoid
   var name: String = "John"
   ```

2. **Use data classes for models**
   ```kotlin
   data class Student(
       val id: String,
       val name: String,
       val email: String
   )
   ```

3. **Sealed classes for states**
   ```kotlin
   sealed class Result<out T> {
       data class Success<T>(val data: T) : Result<T>()
       data class Error(val exception: Exception) : Result<Nothing>()
       object Loading : Result<Nothing>()
   }
   ```

4. **Coroutines for async operations**
   ```kotlin
   viewModelScope.launch {
       val result = repository.getData()
       _uiState.value = result
   }
   ```

5. **Dependency injection with Hilt**
   ```kotlin
   @HiltViewModel
   class MyViewModel @Inject constructor(
       private val repository: MyRepository
   ) : ViewModel()
   ```

## Testing

### Unit Tests

```bash
./gradlew test
```

- Test ViewModels, Use Cases, and Repositories
- Use MockK for mocking
- Aim for >80% code coverage

### Instrumented Tests

```bash
./gradlew connectedAndroidTest
```

- Test UI flows and database operations
- Use Espresso for UI testing

## Pull Request Guidelines

### Before Submitting

- [ ] Code passes all tests (`./gradlew test`)
- [ ] Code passes ktlint check (`./gradlew ktlintCheck`)
- [ ] Code passes detekt check (`./gradlew detekt`)
- [ ] Added tests for new features
- [ ] Updated documentation
- [ ] Tested on physical device
- [ ] Commits follow Conventional Commits format

### PR Description

Use the PR template and include:

- **What**: Brief description of changes
- **Why**: Motivation and context
- **How**: Technical approach
- **Testing**: How you tested the changes
- **Screenshots**: For UI changes

### Code Review Process

1. Automated checks must pass (CI/CD)
2. At least one approving review required
3. Address all review comments
4. Maintain clean commit history

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Provide constructive feedback
- Accept criticism gracefully
- Focus on what's best for the community

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Personal or political attacks
- Publishing private information

### Enforcement

Instances of unacceptable behavior may be reported to support@attendance-system.dev.

## Questions?

- **General**: [Open a Discussion](https://github.com/preethamdev05/face-recognition-attendance-system/discussions)
- **Bugs**: [Create an Issue](https://github.com/preethamdev05/face-recognition-attendance-system/issues/new/choose)
- **Security**: Email support@attendance-system.dev (private)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
