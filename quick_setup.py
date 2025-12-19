#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick Setup and Launch Script
Cybersecurity Toolkit v6.0 - ML Enhanced

This script will:
1. Check for required dependencies
2. Generate synthetic password dataset
3. Train ML model
4. Launch the toolkit

Author: Dr. Mohammed Tawfik
"""

import subprocess
import sys
import os
from pathlib import Path

def print_header():
    """Print welcome header"""
    print("\n" + "="*70)
    print("  Cybersecurity Toolkit v6.0 - Quick Setup")
    print("  ML-Enhanced Password Analysis System")
    print("="*70 + "\n")

def check_dependencies():
    """Check if required packages are installed"""
    print("📦 Checking dependencies...")
    
    required = {
        'pandas': 'pandas',
        'joblib': 'joblib',
        'sklearn': 'scikit-learn'
    }
    
    optional = {
        'shodan': 'shodan',
        'nmap': 'python-nmap',
        'whois': 'python-whois',
        'dns.resolver': 'dnspython',
        'requests': 'requests'
    }
    
    missing = []
    missing_optional = []
    
    # Check required
    for module, package in required.items():
        try:
            __import__(module)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} (REQUIRED)")
            missing.append(package)
    
    # Check optional
    for module, package in optional.items():
        try:
            __import__(module)
            print(f"  ✓ {package} (optional)")
        except ImportError:
            print(f"  ⚠ {package} (optional - some features unavailable)")
            missing_optional.append(package)
    
    if missing:
        print(f"\n❌ Missing required packages: {', '.join(missing)}")
        print("\nInstall with:")
        print(f"  pip install {' '.join(missing)}")
        return False
    
    if missing_optional:
        print(f"\n⚠️  Optional packages not installed: {', '.join(missing_optional)}")
        print("   Some features will be unavailable.")
        print("\nTo install all features:")
        print(f"  pip install {' '.join(missing_optional)}")
    
    print("\n✅ All required dependencies satisfied!\n")
    return True

def generate_dataset():
    """Generate synthetic password dataset"""
    print("🔄 Generating synthetic password dataset...")
    
    if Path("synthetic_password_dataset.csv").exists():
        response = input("  Dataset already exists. Regenerate? (y/n): ")
        if response.lower() != 'y':
            print("  ↳ Using existing dataset")
            return True
    
    try:
        import generator
        print("  ↳ Generating 50,000 synthetic passwords...")
        generator.main()
        print("  ✓ Dataset generated successfully!")
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def train_model():
    """Train ML models"""
    print("\n🤖 Training ML models...")
    
    # Password model
    if Path("pw_strength_model.pkl").exists() and Path("pw_strength_features.json").exists():
        response = input("  Password model exists. Retrain? (y/n): ")
        if response.lower() != 'y':
            print("  ↳ Using existing password model")
        else:
            try:
                import ml_model_trainer
                print("  ↳ Training password strength classifier...")
                ml_model_trainer.main()
                print("  ✓ Password model trained!")
            except Exception as e:
                print(f"  ✗ Error: {e}")
                return False
    else:
        try:
            import ml_model_trainer
            print("  ↳ Training password strength classifier...")
            ml_model_trainer.main()
            print("  ✓ Password model trained!")
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return False
    
    # Hash model
    if Path("hash_identifier_model.pkl").exists() and Path("hash_identifier_features.json").exists():
        response = input("  Hash model exists. Retrain? (y/n): ")
        if response.lower() != 'y':
            print("  ↳ Using existing hash model")
            return True
        
    # Generate hash dataset if needed
    if not Path("hash_training_dataset.csv").exists():
        print("\n  📊 Generating hash training dataset...")
        try:
            import hash_dataset_generator
            hash_dataset_generator.main()
        except Exception as e:
            print(f"  ✗ Error generating hash dataset: {e}")
            return False
    
    # Train hash model
    try:
        import hash_model_trainer
        print("  ↳ Training hash identifier model...")
        hash_model_trainer.main()
        print("  ✓ Hash model trained!")
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False

def launch_toolkit():
    """Launch the main toolkit"""
    print("\n🚀 Launching Cybersecurity Toolkit...")
    print("\nPress Ctrl+C to stop\n")
    print("="*70 + "\n")
    
    try:
        import cybersecurity_toolkit_ML_ENHANCED
        # This will start the GUI
    except KeyboardInterrupt:
        print("\n\n👋 Toolkit closed.")
    except Exception as e:
        print(f"\n✗ Error launching toolkit: {e}")
        return False
    
    return True

def main():
    """Main setup function"""
    print_header()
    
    # Step 1: Check dependencies
    if not check_dependencies():
        print("\n⚠️  Please install required packages and run again.")
        sys.exit(1)
    
    # Step 2: Generate dataset
    print("="*70)
    if not generate_dataset():
        print("\n⚠️  Dataset generation failed.")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Step 3: Train models (password + hash)
    print("="*70)
    if not train_model():
        print("\n⚠️  Model training failed.")
        print("   You can still use the toolkit with rule-based analysis.")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Step 4: Launch toolkit
    print("="*70)
    launch_toolkit()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Setup interrupted. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
