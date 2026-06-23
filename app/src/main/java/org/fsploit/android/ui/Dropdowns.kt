package org.fsploit.android.ui

import android.content.Context
import android.util.TypedValue
import android.widget.ArrayAdapter
import android.widget.Filter
import android.widget.Filterable
import com.google.android.material.textfield.MaterialAutoCompleteTextView
import org.fsploit.android.R

class NonFilteringStringAdapter(
    context: Context,
    items: List<String>
) : ArrayAdapter<String>(context, R.layout.item_dropdown, items.toMutableList()),
    Filterable {

    private val allItems = items.toList()

    override fun getFilter(): Filter {
        return object : Filter() {
            override fun performFiltering(constraint: CharSequence?): FilterResults {
                return FilterResults().apply {
                    values = allItems
                    count = allItems.size
                }
            }

            override fun publishResults(constraint: CharSequence?, results: FilterResults?) {
                clear()
                addAll(allItems)
                notifyDataSetChanged()
            }
        }
    }
}

fun MaterialAutoCompleteTextView.enableFullDropdown() {
    threshold = 0
    setDropDownBackgroundResource(R.drawable.bg_dropdown_popup)
    dropDownVerticalOffset = TypedValue.applyDimension(
        TypedValue.COMPLEX_UNIT_DIP, 6f, resources.displayMetrics
    ).toInt()
    setOnClickListener { showDropDown() }
    setOnFocusChangeListener { _, hasFocus ->
        if (hasFocus) {
            post { showDropDown() }
        }
    }
}
