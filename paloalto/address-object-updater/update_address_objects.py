import panos
from panos.firewall import Firewall
from panos.objects import AddressObject

# Prompt user for firewall or Panorama connection details
def get_connection_details():
    print("Enter the connection details for the Firewall or Panorama:")
    address = input("IP address or hostname: ").strip()
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    return address, username, password

# Connect to the firewall or Panorama
def connect_to_firewall(address, username, password):
    fw = Firewall(address, username, password)
    return fw

# List all address objects and their values
def list_address_objects(fw):
    objects = AddressObject.refreshall(fw)
    print("\nCurrent Address Objects:")
    for idx, obj in enumerate(objects):
        value = obj.value if obj.value else "N/A"
        print(f"{idx + 1}. Name: {obj.name}, Value: {value}, Type: {obj.type}")
    return objects

# Prompt user to select objects to update
def select_objects_to_update(objects):
    selected_indices = []
    while True:
        try:
            choice = input("\nEnter the number of the object to update (or 'done' to finish): ")
            if choice.lower() == 'done':
                break
            index = int(choice) - 1
            if 0 <= index < len(objects):
                selected_indices.append(index)
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Invalid input. Enter a number or 'done'.")
    return [objects[i] for i in selected_indices]

# Prompt for new values and update selected objects
def update_selected_objects(selected_objects):
    updates = []
    for obj in selected_objects:
        print(f"\nUpdating: {obj.name} (Current Value: {obj.value})")
        new_value = input(f"Enter new value for {obj.name} (IP, FQDN, or range): ")
        obj.value = new_value
        updates.append(obj)
    return updates

# Apply batch changes
def apply_batch_changes(fw, updates):
    if updates:
        print("\nApplying changes...")
        for obj in updates:
            obj.apply()  # Update each object on the firewall
        fw.commit()  # Commit all changes in a single batch
        print("Changes committed successfully.")
    else:
        print("No changes to apply.")

# Main execution
def main():
    # Get connection details from user
    address, username, password = get_connection_details()

    # Connect to firewall or Panorama
    fw = connect_to_firewall(address, username, password)
    print(f"Connected to device at {address}")

    # List objects
    all_objects = list_address_objects(fw)

    # Select objects to update
    selected_objects = select_objects_to_update(all_objects)

    # Update selected objects
    updated_objects = update_selected_objects(selected_objects)

    # Apply batch changes
    apply_batch_changes(fw, updated_objects)

if __name__ == "__main__":
    main()