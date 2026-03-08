# Quick Fix: Retrain Models with Current Scikit-Learn Version

If upgrading scikit-learn doesn't work, you can retrain the models with your current version.

## Option 1: Upgrade Scikit-Learn (Recommended)

```bash
# Stop backend (Ctrl+C)
cd backend

# Upgrade
pip uninstall scikit-learn -y
pip install scikit-learn==1.8.0

# If that fails, try:
pip install scikit-learn --upgrade --force-reinstall

# Restart backend
python main.py
```

## Option 2: Use Compatible Pre-trained Models

If you can't upgrade, the models need to be retrained with your version.

**Quick workaround:** Download compatible models or retrain them.

To check your scikit-learn version:

```bash
python -c "import sklearn; print(sklearn.__version__)"
```

## Verification

After upgrading, restart backend and check the warnings:

- ✅ Good: No "InconsistentVersionWarning"
- ❌ Bad: Still seeing version warnings

Then test in app - should work! 🎉
