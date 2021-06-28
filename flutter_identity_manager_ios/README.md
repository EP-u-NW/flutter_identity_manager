# NAME_ios

The iOS implementation of [`NAME`][1].

## Usage

### Import the package

This package has been endorsed, meaning that you only need to add `NAME`
as a dependency in your `pubspec.yaml`. It will be automatically included in your app
when you depend on `package:NAME`.

This is what the above means to your `pubspec.yaml`:

```yaml
...
dependencies:
  ...
  NAME: ^1.0.0
  ...
```

If you wish to use the iOS package only, you can add `NAME_ios` as a
dependency:

```yaml
...
dependencies:
  ...
  NAME_ios: ^1.0.0
  ...
```

[1]: ../NAME