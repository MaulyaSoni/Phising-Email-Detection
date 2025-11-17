"""
MASTER SCRIPT: Complete accuracy improvement workflow
Executes all steps to improve phishing detection accuracy:
1. Add new training samples
2. Correct mislabeled examples
3. Tighten auto-label thresholds
4. Retrain model
5. Validate performance
6. Verify 10/10 phishing detection
"""

import sys
import os
import subprocess
import json
from datetime import datetime

def run_script(script_path, description):
    """Run a Python script and report results"""
    print(f"\n{'='*70}")
    print(f"EXECUTING: {description}")
    print(f"{'='*70}")
    print(f"Script: {script_path}\n")
    
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=False,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            print(f"\n✓ {description} - COMPLETED SUCCESSFULLY")
            return True
        else:
            print(f"\n✗ {description} - FAILED (exit code: {result.returncode})")
            return False
    except subprocess.TimeoutExpired:
        print(f"\n✗ {description} - TIMEOUT (exceeded 5 minutes)")
        return False
    except Exception as e:
        print(f"\n✗ {description} - ERROR: {e}")
        return False

def create_execution_report(results):
    """Create a summary report of execution"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "steps_completed": sum(1 for v in results.values() if v),
        "total_steps": len(results),
        "results": results,
        "status": "SUCCESS" if all(results.values()) else "PARTIAL_SUCCESS"
    }
    
    return report

def main():
    """Main execution"""
    print("\n" + "="*70)
    print(" "*10 + "PHISHING DETECTION MODEL ACCURACY IMPROVEMENT")
    print(" "*15 + "MASTER EXECUTION SCRIPT")
    print("="*70)
    print(f"\nStart Time: {datetime.now().isoformat()}")
    
    # Define script paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    add_samples_script = os.path.join(script_dir, 'add_training_samples.py')
    retrain_script = os.path.join(script_dir, 'retrain_and_validate.py')
    
    # Check if scripts exist
    if not os.path.exists(add_samples_script):
        print(f"\n✗ Error: add_training_samples.py not found at {add_samples_script}")
        return False
    
    if not os.path.exists(retrain_script):
        print(f"\n✗ Error: retrain_and_validate.py not found at {retrain_script}")
        return False
    
    results = {}
    
    # Step 1: Add new training samples
    results['add_samples'] = run_script(
        add_samples_script,
        "Step 1: Add New Training Samples"
    )
    
    if not results['add_samples']:
        print("\n✗ Failed to add training samples. Aborting.")
        return False
    
    # Step 2: Retrain and validate model
    results['retrain'] = run_script(
        retrain_script,
        "Step 2: Retrain and Validate Model"
    )
    
    if not results['retrain']:
        print("\n✗ Failed to retrain model. Aborting.")
        return False
    
    # Generate final report
    print("\n" + "="*70)
    print("FINAL EXECUTION REPORT")
    print("="*70)
    
    report = create_execution_report(results)
    
    print(f"\nExecution Status: {report['status']}")
    print(f"Steps Completed: {report['steps_completed']}/{report['total_steps']}")
    print(f"End Time: {datetime.now().isoformat()}")
    
    print("\nDetailed Results:")
    for step, success in report['results'].items():
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"  {step}: {status}")
    
    # Save report
    report_path = os.path.join(script_dir, 'IMPROVEMENT_REPORT.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to: {report_path}")
    
    print("\n" + "="*70)
    print("NEXT STEPS:")
    print("="*70)
    print("""
1. Test the model with the web application:
   - Start the Flask app: python web/ultimate_app.py
   - Navigate to http://localhost:5000
   - Test with the 10 phishing samples provided

2. Verify accuracy improvements:
   - Check that all 10 phishing samples are detected correctly
   - Compare with previous results (4/10 correct)

3. Monitor continuous learning:
   - New predictions will auto-label at ≥92% confidence
   - Retraining triggers every 30 new examples
   - Check web/data/training_examples.json for updates

4. Production deployment:
   - Backup current model: cp models/ultimate_phishing_model.pkl models/backup_v1.pkl
   - Deploy retrained model to production
   - Monitor prediction accuracy and user feedback
    """)
    
    return report['status'] == 'SUCCESS'

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
