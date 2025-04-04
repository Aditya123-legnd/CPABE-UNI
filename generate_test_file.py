import json
import os
import time

def create_test_file(file_path, size_kb, num_attributes):
    """
    Create a test JSON file with the specified size (in kilobytes) and a variable number 
    of attributes for placement coordinators, internships, training programs, and events.
    This version is tailored for a normal CP-ABE scenario with a fixed encryption policy.
    """
    # Define a fixed encryption policy string (without dynamic attributes)
    policy_str = "BN001 and BS001"
    
    # Base data structure for the test file
    data = {
        "StudentID": "BN001",
        "StudentName": "Andrew N",
        "DateOfBirth": "01/01/2003",
        "Gender": "Male",
        "Major": "Computer Science",
        "CGPA": 8.5,
        "CreditsEarned": 120,
        "PlacementCoordinators": [
            {"CoordinatorID": f"BS00{i}", "Role": f"Placement Coordinator {i}"}
            for i in range(1, num_attributes + 1)
        ],
        "InternshipHistory": [
            {"description": f"Internship {i}"}
            for i in range(1, num_attributes + 1)
        ],
        "TrainingPrograms": [
            {"end_date": f"2022-01-{i:02d}"}
            for i in range(1, num_attributes + 1)
        ],
        "PlacementEvents": [
            {"event": f"Placement Event {i}"}
            for i in range(1, num_attributes + 1)
        ],
        "ContactInformation": {
            "Address": "123 University Ave, Campus Town",
            "MobileNumber": "09xxxxxxxxxx",
            "Email": "xyz@gmail.com"
        },
        "EncryptionPolicy": {
            "Policy": policy_str,
            "DATA": "This is encrypted student record data..."
        }
    }
    
    # Calculate current JSON data size in bytes
    current_size = len(json.dumps(data).encode('utf-8'))
    target_size = size_kb * 1024
    
    # Append additional filler data to approximately reach the target file size
    if current_size < target_size:
        filler_size = target_size - current_size
        data["DATA"] = "A" * filler_size
    else:
        data["DATA"] = "A" * max(0, target_size - 1000)  # fallback adjustment
    
    # Write the JSON data to file
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def main():
    """
    Generate multiple test JSON files with varying file sizes (in KB) and numbers of attributes.
    Files are stored in the 'test_files' directory.
    """
    # Define file sizes in kilobytes and number of attributes to include
    sizes_kb = [1, 10] #[100, 1000]          # File sizes in KB
    num_attributes_list = [1, 5] #[10, 20]    # Number of attributes to include
    
    # Create the directory for test files if it doesn't exist
    os.makedirs("test_files", exist_ok=True)
    
    # Generate and save each test file
    for size_kb in sizes_kb:
        for num_attributes in num_attributes_list:
            file_name = f"test_{size_kb}KB_{num_attributes}attr.json"
            file_path = os.path.join("test_files", file_name)
            create_test_file(file_path, size_kb, num_attributes)
            print(f"Created {file_path}")

if __name__ == '__main__':
    main()
